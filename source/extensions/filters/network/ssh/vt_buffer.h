#pragma once

#include "libvterm/vterm.h"

#include "envoy/buffer/buffer.h"
#include "source/common/common/c_smart_ptr.h"
#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class VTBufferCallbacks {
public:
  virtual ~VTBufferCallbacks() = default;
  virtual void onUpdate(Envoy::Buffer::Instance& buf) PURE;
};

class VTCurrentStateTracker {
public:
  VTCurrentStateTracker(int width = 80, int height = 24);

  void write(const bytes& raw_input);
  void resize(int width, int height);
  void dumpState(Envoy::Buffer::Instance& buffer);

  int width() const { return width_; }
  int height() const { return height_; }

private:
  static int onResize(int rows, int cols, void* user);
  static int onSetTermProp(VTermProp prop, VTermValue* val, void* user);
  static int onMoveCursor(VTermPos pos, VTermPos /*oldpos*/, int /*visible*/, void* user);

  int dumpCellColor(const VTermColor* col, int sgri, std::span<int> sgr, bool fg);
  void dumpCell(Envoy::Buffer::Instance& out, const VTermScreenCell& cell, const VTermScreenCell& prevcell);
  void dumpRow(Envoy::Buffer::Instance& out, int row);
  void dumpTermProps(Envoy::Buffer::Instance& out);

  Envoy::CSmartPtr<VTerm, vterm_free> vterm_;
  int width_{};
  int height_{};
  std::unordered_map<VTermProp, std::variant<bool, int, std::string>> props_;
  VTermPos cursor_{};

  VTermScreen* vterm_screen_; // non-owning
  VTermScreenCallbacks screen_callbacks_{
    .damage = nullptr,
    .moverect = nullptr,
    .movecursor = &onMoveCursor,
    .settermprop = &onSetTermProp,
    .bell = nullptr,
    .resize = &onResize,
    .sb_pushline = nullptr,
    .sb_popline = nullptr,
    .sb_clear = nullptr,
    .sb_pushline4 = nullptr,
  };
};

class VTBuffer {
public:
  VTBuffer(VTBufferCallbacks& cb, int width = 80, int height = 24);

  void write(const bytes& raw_input);
  void resize(int width, int height);
  void dumpState(Envoy::Buffer::Instance& buffer);

  int width() const { return width_; }
  int height() const { return height_; }

private:
  static int onResize(int rows, int cols, void* user);
  static int onDamage(VTermRect rect, void* user);
  static int onPushline(int cols, const VTermScreenCell* cells, void* user);
  static int onSetTermProp(VTermProp prop, VTermValue* val, void* user);
  static int onMoveCursor(VTermPos pos, VTermPos /*oldpos*/, int /*visible*/, void* user);

  int dumpCellColor(const VTermColor* col, int sgri, std::span<int> sgr, bool fg);
  void dumpCell(Envoy::Buffer::Instance& out, const VTermScreenCell& cell, const VTermScreenCell& prevcell);
  void dumpRow(Envoy::Buffer::Instance& out, int row);
  void dumpTermProps(Envoy::Buffer::Instance& out);

  VTBufferCallbacks& callbacks_;
  Envoy::CSmartPtr<VTerm, vterm_free> vterm_;
  int width_{};
  int height_{};
  std::unordered_map<VTermProp, std::variant<bool, int, std::string>> props_;
  VTermPos cursor_{};

  VTermScreen* vterm_screen_; // non-owning
  VTermScreenCallbacks screen_callbacks_{
    .damage = &onDamage, // called when cells have been modified and need to be redrawn
    .moverect = nullptr,
    .movecursor = nullptr,
    // .movecursor = &onMoveCursor,
    .settermprop = &onSetTermProp,
    .bell = nullptr,
    .resize = &onResize,
    .sb_pushline = &onPushline, // called when a line is about to be pushed off screen
    .sb_popline = nullptr,
    .sb_clear = nullptr,
    .sb_pushline4 = nullptr,
  };
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec