#include "source/extensions/filters/network/ssh/vt_buffer.h"

#include "source/common/visit.h"
#include "source/common/span.h"

#include "libvterm/utf8.h"
#pragma clang unsafe_buffer_usage begin
#include "source/common/buffer/buffer_impl.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

VTCurrentStateTracker::VTCurrentStateTracker(int width, int height)
    : width_(width), height_(height) {
  vterm_ = vterm_new(height, width);
  vterm_set_utf8(vterm_.get(), 1);
  vterm_screen_ = vterm_obtain_screen(vterm_.get());
  vterm_screen_set_callbacks(vterm_screen_, &screen_callbacks_, this);
  vterm_screen_enable_altscreen(vterm_screen_, 1);
  vterm_screen_set_damage_merge(vterm_screen_, VTERM_DAMAGE_ROW);
  vterm_screen_reset(vterm_screen_, 1);
}

void VTCurrentStateTracker::write(const bytes& raw_input) {
  vterm_input_write(vterm_.get(), reinterpret_cast<const char*>(raw_input.data()), raw_input.size());
}

void VTCurrentStateTracker::resize(int width, int height) {
  vterm_set_size(vterm_.get(), height, width);
}

void VTCurrentStateTracker::dumpState(Envoy::Buffer::Instance& buffer) {
  dumpTermProps(buffer);
  for (int row = 0; row < height_; row++) {
    dumpRow(buffer, row);
    if (row != height_ - 1) {
      buffer.add("\r\n");
    }
  }
  // move the cursor
  buffer.add(fmt::format("\x1b[{};{}H", cursor_.row + 1, cursor_.col + 1));
}

int VTCurrentStateTracker::onResize(int rows, int cols, void* user) {
  auto* self = static_cast<VTCurrentStateTracker*>(user);
  self->width_ = cols;
  self->height_ = rows;
  return 1;
}

int VTCurrentStateTracker::onSetTermProp(VTermProp prop, VTermValue* val, void* user) {
  auto* self = static_cast<VTCurrentStateTracker*>(user);
  switch (prop) {
  case VTERM_PROP_CURSORVISIBLE: [[fallthrough]];
  case VTERM_PROP_CURSORBLINK:   [[fallthrough]];
  case VTERM_PROP_REVERSE:       [[fallthrough]];
  case VTERM_PROP_ALTSCREEN:     [[fallthrough]];
  case VTERM_PROP_FOCUSREPORT:
    // bool props
    self->props_[prop] = static_cast<bool>(val->boolean);
    break;
  case VTERM_PROP_TITLE: [[fallthrough]];
  case VTERM_PROP_ICONNAME:
    // string props
    if (val->string.str == nullptr || val->string.len == 0) {
      self->props_[prop] = "";
    } else {
      self->props_[prop] = std::string(val->string.str, val->string.len);
    }
    break;
  case VTERM_PROP_CURSORSHAPE: [[fallthrough]];
  case VTERM_PROP_MOUSE:
    // int props
    self->props_[prop] = val->number;
    break;
  default:
    break;
  }
  return 1;
}

int VTCurrentStateTracker::onMoveCursor(VTermPos pos, VTermPos /*oldpos*/, int /*visible*/, void* user) {
  auto* self = static_cast<VTCurrentStateTracker*>(user);
  self->cursor_ = pos;
  return 1;
}

int VTCurrentStateTracker::dumpCellColor(const VTermColor* col, int sgri, std::span<int> sgr, bool fg) {
  /* Reset the color if the given color is the default color */
  if (fg && VTERM_COLOR_IS_DEFAULT_FG(col)) {
    sgr[sgri++] = 39;
    return sgri;
  }
  if (!fg && VTERM_COLOR_IS_DEFAULT_BG(col)) {
    sgr[sgri++] = 49;
    return sgri;
  }

  /* Decide whether to send an indexed color or an RGB color */
  if (VTERM_COLOR_IS_INDEXED(col)) {
    const uint8_t idx = col->indexed.idx;
    if (idx < 8) {
      sgr[sgri++] = (idx + (fg ? 30 : 40));
    } else if (idx < 16) {
      sgr[sgri++] = (idx - 8 + (fg ? 90 : 100));
    } else {
      sgr[sgri++] = (fg ? 38 : 48);
      sgr[sgri++] = 5;
      sgr[sgri++] = idx;
    }
  } else if (VTERM_COLOR_IS_RGB(col)) {
    sgr[sgri++] = (fg ? 38 : 48);
    sgr[sgri++] = 2;
    sgr[sgri++] = col->rgb.red;
    sgr[sgri++] = col->rgb.green;
    sgr[sgri++] = col->rgb.blue;
  }
  return sgri;
}

void VTCurrentStateTracker::dumpCell(Envoy::Buffer::Instance& out, const VTermScreenCell& cell, const VTermScreenCell& prevcell) {
  //  If all 7 attributes change, that means 7 SGRs max
  //  Each colour could consume up to 5 entries
  std::array<int, 7 + 2 * 5> sgr;
  int sgri = 0;

  if (!prevcell.attrs.bold && cell.attrs.bold) {
    sgr[sgri++] = 1;
  }
  if (prevcell.attrs.bold && !cell.attrs.bold) {
    sgr[sgri++] = 22;
  }

  if ((prevcell.attrs.underline == 0u) && (cell.attrs.underline != 0u)) {
    sgr[sgri++] = 4;
  }
  if ((prevcell.attrs.underline != 0u) && (cell.attrs.underline == 0u)) {
    sgr[sgri++] = 24;
  }

  if (!prevcell.attrs.italic && cell.attrs.italic) {
    sgr[sgri++] = 3;
  }
  if (prevcell.attrs.italic && !cell.attrs.italic) {
    sgr[sgri++] = 23;
  }

  if (!prevcell.attrs.blink && cell.attrs.blink) {
    sgr[sgri++] = 5;
  }
  if (prevcell.attrs.blink && !cell.attrs.blink) {
    sgr[sgri++] = 25;
  }

  if (!prevcell.attrs.reverse && cell.attrs.reverse) {
    sgr[sgri++] = 7;
  }
  if (prevcell.attrs.reverse && !cell.attrs.reverse) {
    sgr[sgri++] = 27;
  }

  if (!prevcell.attrs.conceal && cell.attrs.conceal) {
    sgr[sgri++] = 8;
  }
  if (prevcell.attrs.conceal && !cell.attrs.conceal) {
    sgr[sgri++] = 28;
  }

  if (!prevcell.attrs.strike && cell.attrs.strike) {
    sgr[sgri++] = 9;
  }
  if (prevcell.attrs.strike && !cell.attrs.strike) {
    sgr[sgri++] = 29;
  }

  if ((prevcell.attrs.font == 0u) && (cell.attrs.font != 0u)) {
    sgr[sgri++] = 10 + cell.attrs.font;
  }
  if ((prevcell.attrs.font != 0u) && (cell.attrs.font == 0u)) {
    sgr[sgri++] = 10;
  }

  if (!static_cast<bool>(vterm_color_is_equal(&prevcell.fg, &cell.fg))) {
    sgri = dumpCellColor(&cell.fg, sgri, sgr, true);
  }

  if (!static_cast<bool>(vterm_color_is_equal(&prevcell.bg, &cell.bg))) {
    sgri = dumpCellColor(&cell.bg, sgri, sgr, false);
  }

  if (sgri > 0) {
    out.add("\x1b[");
    for (int i = 0; i < sgri; i++) {
      if (i == 0) {
        out.add(fmt::format("{:d}", CSI_ARG(sgr[i])));
      } else {
        if (CSI_ARG_HAS_MORE(sgr[i])) {
          out.add(fmt::format(":{:d}", CSI_ARG(sgr[i])));
        } else {
          out.add(fmt::format(";{:d}", CSI_ARG(sgr[i])));
        }
      }
    }
    out.add("m");
  }

  auto chars = std::span{cell.chars};
  for (size_t i = 0; i < chars.size() && (chars[i] != 0u); i++) {
    std::array<char, 6> bytes;
    auto n = fill_utf8(chars[i], bytes.data());
    ASSERT(n <= 6);
    out.add(std::string_view{unsafe_forge_span(bytes.data(), n)});
  }
}

void VTCurrentStateTracker::dumpRow(Envoy::Buffer::Instance& out, int row) {
  VTermPos pos = {.row = row, .col = 0};
  VTermScreenCell prevcell{};
  vterm_state_get_default_colors(vterm_obtain_state(vterm_.get()), &prevcell.fg,
                                 &prevcell.bg);

  while (pos.col < width_) {
    VTermScreenCell cell{};
    if (!static_cast<bool>(vterm_screen_get_cell(vterm_screen_, pos, &cell))) {
      return;
    }

    dumpCell(out, cell, prevcell);

    pos.col += cell.width;
    prevcell = cell;
  }

  if (prevcell.attrs.bold || (prevcell.attrs.underline != 0u) || prevcell.attrs.italic ||
      prevcell.attrs.blink || prevcell.attrs.reverse || prevcell.attrs.strike ||
      prevcell.attrs.conceal || (prevcell.attrs.font != 0u)) {
    out.add("\x1b[m");
  }
}

void VTCurrentStateTracker::dumpTermProps(Envoy::Buffer::Instance& out) {
  for (auto&& [prop, value] : props_) {
    auto str = std::visit(
      make_overloads_no_validation(
        [&](bool value) {
          switch (prop) {
          case VTERM_PROP_CURSORVISIBLE:
            return value ? "\x1b[?25h"s : "\x1b[?25l"s;
          case VTERM_PROP_CURSORBLINK:
            return value ? "\x1b[?12h"s : "\x1b[?12l"s;
          case VTERM_PROP_REVERSE:
            return value ? "\x1b[7m"s : "\x1b[27m"s;
          case VTERM_PROP_ALTSCREEN:
            return value ? "\x1b[?1049h"s : "\x1b[?1049l"s;
          case VTERM_PROP_FOCUSREPORT:
            return value ? "\x1b[?1004h"s : "\x1b[?1004l"s;
          default:
          }
          return ""s;
        },
        [&](int value) {
          switch (prop) {
          case VTERM_PROP_CURSORSHAPE:
            switch (value) {
            case 0: return "\x1b[?2c"s; // block cursor
            case 1: return "\x1b[?6c"s; // underline cursor
            case 2: return "\x1b[?4c"s; // bar cursor
            }
            break;
          case VTERM_PROP_MOUSE:
            switch (value) {
            case 0: return "\x1b[?1000l"s; // disable mouse reporting
            case 1: return "\x1b[?1000h"s; // enable mouse reporting
            case 2: return "\x1b[?1002h"s; // enable mouse drag reporting
            case 3: return "\x1b[?1003h"s; // enable mouse motion reporting
            }
            break;
          default:
          }
          return ""s;
        },
        [&](const std::string& value) {
          switch (prop) {
          case VTERM_PROP_TITLE:
            return fmt::format("\x1b]2;{}\a", value);
          case VTERM_PROP_ICONNAME:
            return fmt::format("\x1b]1;{}\a", value);
          default:
          }
          return ""s;
        }),
      value);
    if (!str.empty()) {
      out.add(str);
    }
  }
}

VTBuffer::VTBuffer(VTBufferCallbacks& cb, int width, int height)
    : callbacks_(cb), width_(width), height_(height) {
  vterm_ = vterm_new(height, width);
  vterm_set_utf8(vterm_.get(), 1);
  vterm_screen_ = vterm_obtain_screen(vterm_.get());
  vterm_screen_set_callbacks(vterm_screen_, &screen_callbacks_, this);
  vterm_screen_enable_altscreen(vterm_screen_, 1);
  vterm_screen_set_damage_merge(vterm_screen_, VTERM_DAMAGE_CELL);
  vterm_screen_reset(vterm_screen_, 1);
}

void VTBuffer::write(const bytes& raw_input) {
  vterm_input_write(vterm_.get(), reinterpret_cast<const char*>(raw_input.data()), raw_input.size());
}

void VTBuffer::resize(int width, int height) {
  vterm_set_size(vterm_.get(), height, width);
}

void VTBuffer::dumpState(Envoy::Buffer::Instance& buffer) {
  dumpTermProps(buffer);
  for (int row = 0; row < height_; row++) {
    dumpRow(buffer, row);
    if (row != height_ - 1) {
      buffer.add("\r\n");
    }
  }
  // move the cursor
  buffer.add(fmt::format("\x1b[{};{}H", cursor_.row + 1, cursor_.col + 1));
}

int VTBuffer::onResize(int rows, int cols, void* user) {
  auto* self = static_cast<VTBuffer*>(user);
  self->width_ = cols;
  self->height_ = rows;
  return 1;
}

int VTBuffer::onDamage(VTermRect rect, void* user) {
  auto* self = static_cast<VTBuffer*>(user);
  Envoy::Buffer::OwnedImpl buf;
  // hide the cursor
  buf.add("\x1b[?25l");
  VTermPos saved_cursor = self->cursor_;

  VTermColor default_fg{};
  VTermColor default_bg{};
  vterm_state_get_default_colors(vterm_obtain_state(self->vterm_.get()), &default_fg, &default_bg);
  VTermScreenCell prevcell{};
  prevcell.fg = default_fg;
  prevcell.bg = default_bg;

  // ranges are exclusive, i.e. [start_row, end_row)
  for (auto i = rect.start_row; i < rect.end_row; i++) {
    // move the cursor to the start of the damaged part of the row
    buf.add(fmt::format("\x1b[{};0H", i + 1));
    // buf.add(fmt::format("\x1b[{};{}H", i + 1, rect.start_col + 1));
    // clear from the start col to end col for this row
    // buf.add(fmt::format("\x1b[{}X", rect.end_col - rect.start_col));
    buf.add(fmt::format("\x1b[K"));
    // draw from the row view
    VTermPos pos = {.row = i, .col = 0};
    prevcell = {};
    prevcell.fg = default_fg;
    prevcell.bg = default_bg;

    while (pos.col < rect.end_col) {
      VTermScreenCell cell{};
      if (!static_cast<bool>(vterm_screen_get_cell(self->vterm_screen_, pos, &cell))) {
        return 0;
      }

      self->dumpCell(buf, cell, prevcell);

      pos.col += cell.width;
      prevcell = cell;
    }

    if (prevcell.attrs.bold || (prevcell.attrs.underline != 0u) || prevcell.attrs.italic ||
        prevcell.attrs.blink || prevcell.attrs.reverse || prevcell.attrs.strike ||
        prevcell.attrs.conceal || (prevcell.attrs.font != 0u)) {
      buf.add("\x1b[m");
    }
  }
  // reset colors if the last cell written had non-default background or foreground
  if (vterm_color_is_equal(&prevcell.fg, &default_fg) == 0 || vterm_color_is_equal(&prevcell.bg, &default_bg) == 0) {
    // resets colors only, not effects
    buf.add("\x1b[39;49m");
  }
  // move the cursor back to the saved position
  buf.add(fmt::format("\x1b[{};{}H", saved_cursor.row + 1, saved_cursor.col + 1));
  // show the cursor
  buf.add("\x1b[?25h");
  self->callbacks_.onUpdate(buf);
  return 1;
}

int VTBuffer::onPushline(int cols, const VTermScreenCell* cells, void* user) {
  (void)cols;
  (void)cells;
  (void)user;
  return 1;
}

int VTBuffer::onSetTermProp(VTermProp prop, VTermValue* val, void* user) {
  auto* self = static_cast<VTBuffer*>(user);
  switch (prop) {
  case VTERM_PROP_CURSORVISIBLE: [[fallthrough]];
  case VTERM_PROP_CURSORBLINK:   [[fallthrough]];
  case VTERM_PROP_REVERSE:       [[fallthrough]];
  case VTERM_PROP_ALTSCREEN:     [[fallthrough]];
  case VTERM_PROP_FOCUSREPORT:
    // bool props
    self->props_[prop] = static_cast<bool>(val->boolean);
    break;
  case VTERM_PROP_TITLE: [[fallthrough]];
  case VTERM_PROP_ICONNAME:
    // string props
    if (val->string.str == nullptr || val->string.len == 0) {
      self->props_[prop] = "";
    } else {
      self->props_[prop] = std::string(val->string.str, val->string.len);
    }
    break;
  case VTERM_PROP_CURSORSHAPE: [[fallthrough]];
  case VTERM_PROP_MOUSE:
    // int props
    self->props_[prop] = val->number;
    break;
  default:
    break;
  }
  return 1;
}

int VTBuffer::onMoveCursor(VTermPos pos, VTermPos /*oldpos*/, int /*visible*/, void* user) {
  auto* self = static_cast<VTBuffer*>(user);
  self->cursor_ = pos;
  return 1;
}

int VTBuffer::dumpCellColor(const VTermColor* col, int sgri, std::span<int> sgr, bool fg) {
  /* Reset the color if the given color is the default color */
  if (fg && VTERM_COLOR_IS_DEFAULT_FG(col)) {
    sgr[sgri++] = 39;
    return sgri;
  }
  if (!fg && VTERM_COLOR_IS_DEFAULT_BG(col)) {
    sgr[sgri++] = 49;
    return sgri;
  }

  /* Decide whether to send an indexed color or an RGB color */
  if (VTERM_COLOR_IS_INDEXED(col)) {
    const uint8_t idx = col->indexed.idx;
    if (idx < 8) {
      sgr[sgri++] = (idx + (fg ? 30 : 40));
    } else if (idx < 16) {
      sgr[sgri++] = (idx - 8 + (fg ? 90 : 100));
    } else {
      sgr[sgri++] = (fg ? 38 : 48);
      sgr[sgri++] = 5;
      sgr[sgri++] = idx;
    }
  } else if (VTERM_COLOR_IS_RGB(col)) {
    sgr[sgri++] = (fg ? 38 : 48);
    sgr[sgri++] = 2;
    sgr[sgri++] = col->rgb.red;
    sgr[sgri++] = col->rgb.green;
    sgr[sgri++] = col->rgb.blue;
  }
  return sgri;
}

void VTBuffer::dumpCell(Envoy::Buffer::Instance& out, const VTermScreenCell& cell, const VTermScreenCell& prevcell) {
  //  If all 7 attributes change, that means 7 SGRs max
  //  Each colour could consume up to 5 entries
  std::array<int, 7 + 2 * 5> sgr;
  int sgri = 0;

  if (!prevcell.attrs.bold && cell.attrs.bold) {
    sgr[sgri++] = 1;
  }
  if (prevcell.attrs.bold && !cell.attrs.bold) {
    sgr[sgri++] = 22;
  }

  if ((prevcell.attrs.underline == 0u) && (cell.attrs.underline != 0u)) {
    sgr[sgri++] = 4;
  }
  if ((prevcell.attrs.underline != 0u) && (cell.attrs.underline == 0u)) {
    sgr[sgri++] = 24;
  }

  if (!prevcell.attrs.italic && cell.attrs.italic) {
    sgr[sgri++] = 3;
  }
  if (prevcell.attrs.italic && !cell.attrs.italic) {
    sgr[sgri++] = 23;
  }

  if (!prevcell.attrs.blink && cell.attrs.blink) {
    sgr[sgri++] = 5;
  }
  if (prevcell.attrs.blink && !cell.attrs.blink) {
    sgr[sgri++] = 25;
  }

  if (!prevcell.attrs.reverse && cell.attrs.reverse) {
    sgr[sgri++] = 7;
  }
  if (prevcell.attrs.reverse && !cell.attrs.reverse) {
    sgr[sgri++] = 27;
  }

  if (!prevcell.attrs.conceal && cell.attrs.conceal) {
    sgr[sgri++] = 8;
  }
  if (prevcell.attrs.conceal && !cell.attrs.conceal) {
    sgr[sgri++] = 28;
  }

  if (!prevcell.attrs.strike && cell.attrs.strike) {
    sgr[sgri++] = 9;
  }
  if (prevcell.attrs.strike && !cell.attrs.strike) {
    sgr[sgri++] = 29;
  }

  if ((prevcell.attrs.font == 0u) && (cell.attrs.font != 0u)) {
    sgr[sgri++] = 10 + cell.attrs.font;
  }
  if ((prevcell.attrs.font != 0u) && (cell.attrs.font == 0u)) {
    sgr[sgri++] = 10;
  }

  if (!static_cast<bool>(vterm_color_is_equal(&prevcell.fg, &cell.fg))) {
    sgri = dumpCellColor(&cell.fg, sgri, sgr, true);
  }

  if (!static_cast<bool>(vterm_color_is_equal(&prevcell.bg, &cell.bg))) {
    sgri = dumpCellColor(&cell.bg, sgri, sgr, false);
  }

  if (sgri > 0) {
    out.add("\x1b[");
    for (int i = 0; i < sgri; i++) {
      if (i == 0) {
        out.add(fmt::format("{:d}", CSI_ARG(sgr[i])));
      } else {
        if (CSI_ARG_HAS_MORE(sgr[i])) {
          out.add(fmt::format(":{:d}", CSI_ARG(sgr[i])));
        } else {
          out.add(fmt::format(";{:d}", CSI_ARG(sgr[i])));
        }
      }
    }
    out.add("m");
  }

  auto chars = std::span{cell.chars};
  for (size_t i = 0; i < chars.size() && (chars[i] != 0u); i++) {
    std::array<char, 6> bytes;
    auto n = fill_utf8(chars[i], bytes.data());
    ASSERT(n <= 6);
    out.add(std::string_view{unsafe_forge_span(bytes.data(), n)});
  }
}

void VTBuffer::dumpRow(Envoy::Buffer::Instance& out, int row) {
  VTermPos pos = {.row = row, .col = 0};
  VTermScreenCell prevcell{};
  vterm_state_get_default_colors(vterm_obtain_state(vterm_.get()), &prevcell.fg,
                                 &prevcell.bg);

  while (pos.col < width_) {
    VTermScreenCell cell{};
    if (!static_cast<bool>(vterm_screen_get_cell(vterm_screen_, pos, &cell))) {
      return;
    }

    dumpCell(out, cell, prevcell);

    pos.col += cell.width;
    prevcell = cell;
  }

  if (prevcell.attrs.bold || (prevcell.attrs.underline != 0u) || prevcell.attrs.italic ||
      prevcell.attrs.blink || prevcell.attrs.reverse || prevcell.attrs.strike ||
      prevcell.attrs.conceal || (prevcell.attrs.font != 0u)) {
    out.add("\x1b[m");
  }
}

void VTBuffer::dumpTermProps(Envoy::Buffer::Instance& out) {
  for (auto&& [prop, value] : props_) {
    auto str = std::visit(
      make_overloads_no_validation(
        [&](bool value) {
          switch (prop) {
          case VTERM_PROP_CURSORVISIBLE:
            return value ? "\x1b[?25h"s : "\x1b[?25l"s;
          case VTERM_PROP_CURSORBLINK:
            return value ? "\x1b[?12h"s : "\x1b[?12l"s;
          case VTERM_PROP_REVERSE:
            return value ? "\x1b[7m"s : "\x1b[27m"s;
          case VTERM_PROP_ALTSCREEN:
            return value ? "\x1b[?1049h"s : "\x1b[?1049l"s;
          case VTERM_PROP_FOCUSREPORT:
            return value ? "\x1b[?1004h"s : "\x1b[?1004l"s;
          default:
          }
          return ""s;
        },
        [&](int value) {
          switch (prop) {
          case VTERM_PROP_CURSORSHAPE:
            switch (value) {
            case 0: return "\x1b[?2c"s; // block cursor
            case 1: return "\x1b[?6c"s; // underline cursor
            case 2: return "\x1b[?4c"s; // bar cursor
            }
            break;
          case VTERM_PROP_MOUSE:
            switch (value) {
            case 0: return "\x1b[?1000l"s; // disable mouse reporting
            case 1: return "\x1b[?1000h"s; // enable mouse reporting
            case 2: return "\x1b[?1002h"s; // enable mouse drag reporting
            case 3: return "\x1b[?1003h"s; // enable mouse motion reporting
            }
            break;
          default:
          }
          return ""s;
        },
        [&](const std::string& value) {
          switch (prop) {
          case VTERM_PROP_TITLE:
            return fmt::format("\x1b]2;{}\a", value);
          case VTERM_PROP_ICONNAME:
            return fmt::format("\x1b]1;{}\a", value);
          default:
          }
          return ""s;
        }),
      value);
    if (!str.empty()) {
      out.add(str);
    }
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
