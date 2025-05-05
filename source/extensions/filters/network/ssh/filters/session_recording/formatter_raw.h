#pragma once

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/filters/session_recording/raw_format.pb.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/filters/session_recording/formatter.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

using pomerium::extensions::ssh::SSHDownstreamPTYInfo;
using pomerium::extensions::ssh::filters::session_recording::raw_format::Header;
using pomerium::extensions::ssh::filters::session_recording::raw_format::Packet;
using pomerium::extensions::ssh::filters::session_recording::raw_format::PacketDirection;

template <OutputBufferType T>
class RawFormatter : public OutputBufferFormatter<T> {
public:
  RawFormatter(std::unique_ptr<T> output_buffer, absl::Time start_time, bool encrypted)
      : OutputBufferFormatter<T>(std::move(output_buffer), start_time),
        encrypted_(encrypted),
        start_time_(start_time),
        last_packet_time_(start_time) {
  }
  constexpr Format format() const override { return Format::RawFormat; }

  void writeHeader(const SSHDownstreamPTYInfo& handoff_info) override {
    Header h;
    h.set_start_time(absl::ToUnixMillis(start_time_));
    h.set_encrypted(encrypted_);
    *h.mutable_pty_info() = handoff_info;
    writeProtodelim(h);
  }

  void writeHeader(const wire::PtyReqChannelRequestMsg& msg) override {
    Header h;
    h.set_start_time(absl::ToUnixMillis(start_time_));
    h.set_encrypted(encrypted_);
    SSHDownstreamPTYInfo pty_info;
    *pty_info.mutable_term_env() = msg.term_env;
    pty_info.set_width_columns(msg.width_columns);
    pty_info.set_height_rows(msg.height_rows);
    pty_info.set_width_columns(msg.width_columns);
    pty_info.set_width_px(msg.width_px);
    *pty_info.mutable_modes() = msg.modes;
    *h.mutable_pty_info() = pty_info;
    writeProtodelim(h);
  }

  void writeResizeEvent(const wire::WindowDimensionChangeChannelRequestMsg& msg) override {
    auto p = newPacket();
    p.set_direction(PacketDirection::DownstreamToUpstream);
    encodeToPacket(p, msg);
    writeProtodelim(p);
  }

  void writeOutputEvent(const wire::ChannelDataMsg& msg) override {
    auto p = newPacket();
    p.set_direction(PacketDirection::UpstreamToDownstream);
    *p.mutable_channel_data() = std::string_view{reinterpret_cast<const char*>(msg.data->data()), msg.data->size()};
    writeProtodelim(p);
  }

  void writeInputEvent(const wire::ChannelDataMsg& msg) override {
    auto p = newPacket();
    p.set_direction(PacketDirection::DownstreamToUpstream);
    *p.mutable_channel_data() = std::string_view{reinterpret_cast<const char*>(msg.data->data()), msg.data->size()};
    writeProtodelim(p);
  }

  void writeTrailer(const wire::Message& msg, absl::Time end_time) override {
    msg.visit(
      [&](const wire::DisconnectMsg& msg) {
        Packet p;
        p.set_direction(PacketDirection::UpstreamToDownstream);
        p.set_time_delta_ms(absl::ToInt64Milliseconds(end_time - last_packet_time_));
        last_packet_time_ = end_time;
        encodeToPacket(p, msg);
        writeProtodelim(p);
      },
      [](const auto&) {});
  }

private:
  inline void ensureBufferSizeAtLeast(size_t at_least) {
    if (buffer_.size() < at_least) {
      buffer_.resize(at_least);
    }
  }

  void encodeToPacket(Packet& packet, wire::Encoder auto const& msg) {
    Envoy::Buffer::OwnedImpl tmp;
    auto n = msg.encode(tmp);
    if (n.ok()) {
      auto len = tmp.length();
      ASSERT(*n == len);
      packet.mutable_ssh_message()->resize(len);
      tmp.copyOut(0, len, packet.mutable_ssh_message()->data());
      tmp.drain(len);
    }
  }

  size_t writeProtodelim(google::protobuf::MessageLite& msg) {
    size_t size = msg.ByteSizeLong();
    size_t varintSize = google::protobuf::io::CodedOutputStream::VarintSize64(size);
    ensureBufferSizeAtLeast(varintSize + size);
    auto bufferView = std::span(buffer_).first(varintSize + size);
    writeVarintWithSize(size, bufferView.first(varintSize));
    msg.SerializeWithCachedSizesToArray(bufferView.subspan(varintSize, size).data());
    this->output().add(bufferView);
    return size;
  }

  inline Packet newPacket() {
    Packet p;
    auto now = absl::Now();
    auto delta = now - last_packet_time_;
    p.set_time_delta_ms(absl::ToInt64Milliseconds(delta));
    last_packet_time_ = now;
    return p;
  }

  inline void writeVarintWithSize(uint64_t value, std::span<uint8_t> out) {
    ASSERT(out.size() > 0);
    for (size_t i = 0; i < out.size() - 1; i++) {
      out[i] = (value & 0x7F) | 0x80;
      value >>= 7;
    }
    out.back() = static_cast<uint8_t>(value);
  }

  bool encrypted_;
  bytes buffer_;
  absl::Time start_time_;
  absl::Time last_packet_time_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording