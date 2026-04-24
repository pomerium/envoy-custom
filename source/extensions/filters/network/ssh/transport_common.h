#pragma once

#pragma clang unsafe_buffer_usage begin
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#pragma clang unsafe_buffer_usage end
#include "source/extensions/filters/network/ssh/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

static constexpr DirectionTags clientKeys{'A', 'C', 'E'};
static constexpr DirectionTags serverKeys{'B', 'D', 'F'};

enum class ChannelMode {
  // Normal mode: the channel is being proxied directly to the upstream.
  Normal = 1,

  // Hijacked mode: only the server codec is active, and the upstream side of the channel is being
  // redirected to Pomerium.
  Hijacked = 2,

  // Handoff mode: the channel was previously in Hijacked mode, but Pomerium has handed off the
  // upstream side of the channel to the real upstream server. This is a permanent state, and
  // signals some extra logic such as performing channel ID translation.
  Handoff = 3,

  // Mirror mode: no upstream; contents are duplicated from a different channel to mirror its state.
  Mirror = 4,
};

enum class MultiplexMode {
  None = 0,
  Source = 1,
  Mirror = 2,
};

enum class ReadWriteMode {
  ReadOnly = 0,
  ReadWrite = 1,
};

struct HandoffInfo {
  bool handoff_in_progress{};
  std::unique_ptr<pomerium::extensions::ssh::SSHDownstreamChannelInfo> channel_info;
  std::unique_ptr<pomerium::extensions::ssh::SSHDownstreamPTYInfo> pty_info;
};

struct MultiplexingInfo {
  MultiplexMode multiplex_mode{MultiplexMode::None};
  ReadWriteMode rw_mode{ReadWriteMode::ReadOnly};
  stream_id_t source_stream_id{};
  std::optional<uint32_t> downstream_channel_id;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec