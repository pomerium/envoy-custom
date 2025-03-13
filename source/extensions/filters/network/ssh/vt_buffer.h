#pragma once

#include "libvterm/vterm.h"
#include "libvterm/utf8.h"
#include "source/extensions/filters/network/ssh/wire/util.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class VTBuffer {
public:
  VTBuffer(int width = 80, int height = 24)
      : width_(width), height_(height) {
    vterm_ = vterm_new(height, width);
    vterm_set_utf8(vterm_.get(), 1);
    vterm_screen_ = vterm_obtain_screen(vterm_.get());
    vterm_screen_set_callbacks(vterm_screen_, &callbacks_, this);
    vterm_screen_enable_altscreen(vterm_screen_, 1);
    vterm_screen_enable_reflow(vterm_screen_, true);
    vterm_screen_reset(vterm_screen_, 1);
  }

  void write(const bytes& raw_input) {
    vterm_input_write(vterm_.get(), reinterpret_cast<const char*>(raw_input.data()), raw_input.size());
  }
  void resize(int width, int height) {
    vterm_set_size(vterm_.get(), height, width);
  }
  void dumpState(Envoy::Buffer::Instance& buffer) {
    dumpTermProps(buffer);
    for (int row = 0; row < height_; row++) {
      dumpRow(buffer, row);
    }
    // move the cursor
    buffer.add(fmt::format("\x1b[{};{}H", cursor_.row + 1, cursor_.col + 1));
  }

  int width() const { return width_; }
  int height() const { return height_; }

private:
  static int onResize(int rows, int cols, void* user) {
    auto* self = static_cast<VTBuffer*>(user);
    self->width_ = cols;
    self->height_ = rows;
    return 1;
  }

  static int onSetTermProp(VTermProp prop, VTermValue* val, void* user) {
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

  static int onMoveCursor(VTermPos pos, VTermPos /*oldpos*/, int /*visible*/, void* user) {
    auto* self = static_cast<VTBuffer*>(user);
    self->cursor_ = pos;
    return 1;
  }
  // static int onPushline(int cols, const VTermScreenCell* cells, void* user) {
  //   auto* self = static_cast<VTBuffer*>(user);
  //   VTermScreenCell prevcell{};
  //   vterm_state_get_default_colors(vterm_obtain_state(self->vterm_.get()), &prevcell.fg, &prevcell.bg);

  //   for (int col = 0; col < cols; col++) {
  //     dumpCell(cells + col, &prevcell);
  //     prevcell = cells[col];
  //   }

  //   dumpEol(buffer, prevcell);
  //   return 1;
  // }

  int dumpCellColor(const VTermColor* col, int sgri, std::span<int> sgr, bool fg) {
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

  void dumpCell(Envoy::Buffer::Instance& out, const VTermScreenCell& cell, const VTermScreenCell& prevcell) {
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
      for (int i = 0; i < sgri; i++)
        if (i == 0) {
          out.add(fmt::format("{:d}", CSI_ARG(sgr[i])));
        } else {
          if (CSI_ARG_HAS_MORE(sgr[i])) {
            out.add(fmt::format(":{:d}", CSI_ARG(sgr[i])));
          } else {
            out.add(fmt::format(";{:d}", CSI_ARG(sgr[i])));
          }
        }
      out.add("m");
    }

    for (int i = 0; i < VTERM_MAX_CHARS_PER_CELL && (cell.chars[i] != 0u); i++) {
      std::array<char, 6> bytes;
      auto n = fill_utf8(cell.chars[i], bytes.data());
      ASSERT(n <= 6);
      out.add(std::string_view{unsafe_forge_span(bytes.data(), n)});
    }
  }

  void dumpRow(Envoy::Buffer::Instance& out, int row) {
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

    // FIXME: this is definitely wrong
    if (row < height_ - 1) {
      out.add("\r\n");
    }
  }

  void dumpTermProps(Envoy::Buffer::Instance& out) {
    for (auto&& [prop, value] : props_) {
      auto str = std::visit(
        overloads{
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
          },
        },
        value);
      if (!str.empty()) {
        out.add(str);
      }
    }
  }

  Envoy::CSmartPtr<VTerm, vterm_free> vterm_;
  int width_{};
  int height_{};
  std::unordered_map<VTermProp, std::variant<bool, int, std::string>> props_;
  VTermPos cursor_{};

  VTermScreen* vterm_screen_; // non-owning
  VTermScreenCallbacks callbacks_{
    .damage = nullptr,
    .moverect = nullptr,
    .movecursor = &onMoveCursor,
    .settermprop = &onSetTermProp,
    .bell = nullptr,
    .resize = &onResize,
    .sb_pushline = nullptr,
    // .sb_pushline = &onPushline,
    .sb_popline = nullptr,
    .sb_clear = nullptr,
    .sb_pushline4 = nullptr,
  };
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec