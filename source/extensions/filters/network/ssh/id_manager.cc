#include "source/extensions/filters/network/ssh/id_manager.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

absl::Status ChannelIDManager::processIncomingChannelOpenMsg(wire::ChannelOpenMsg& msg, Peer source) {
  switch (source) {
  case Peer::Downstream: {
    internalChannelInfo mappings{
      // .opened_by = source,
      .downstream_id = msg.sender_channel,
    };
    auto newInternalId = id_alloc_.alloc();
    if (!newInternalId.ok()) {
      return newInternalId.status();
    }
    internal_channels_[*newInternalId] = mappings;
  } break;
  case Peer::Upstream: {
    internalChannelInfo mappings{
      // .opened_by = source,
      .upstream_id = msg.sender_channel,
    };
    auto newInternalId = id_alloc_.alloc();
    if (!newInternalId.ok()) {
      return newInternalId.status();
    }
    internal_channels_[*newInternalId] = mappings;
  } break;
    // case Source::Internal:
    //   internal_channels_[msg.sender_channel] = internalChannelInfo{
    //     .opened_by = source,
    //   };
    //   break;
  }
  return absl::OkStatus();
}

// absl::Status ChannelIDManager::processOutgoingChannelOpenConfirmationMsg(wire::ChannelOpenConfirmationMsg& msg, Dest dest) {
//   auto internalId = *msg.recipient_channel;
//   auto it = internal_channels_.find(internalId);
//   if (it == internal_channels_.end()) {
//     return absl::InvalidArgumentError(fmt::format("unknown channel {} in ChannelOpenConfirmationMsg", *msg.recipient_channel));
//   }

//   auto& info = it->second;
//   switch (info.opened_by) {
//   case Source::Downstream:
//     // ChannelOpenConfirmation sent by the downstream in response to an open request
//     info.downstream_id = msg.sender_channel;
//     msg.sender_channel = internalId;
//     if (dest == Dest::Upstream) {
//       ASSERT(info.upstream_id.has_value());
//       msg.recipient_channel = info.upstream_id.value();
//     }
//     break;
//   case Source::Upstream:
//     // ChannelOpenConfirmation sent by the upstream in response to an open request
//     info.upstream_id = msg.sender_channel;
//     msg.sender_channel = internalId;
//     if (dest == Dest::Downstream) {
//       ASSERT(info.downstream_id.has_value());
//       msg.recipient_channel = info.downstream_id.value();
//     }
//     break;
//   // case Source::Internal:
//   //   // ChannelOpenConfirmation sent by us; the IDs will already be correct, just keep track of
//   //   // the recipient channel
//   //   switch (dest) {
//   //   case Dest::Downstream:
//   //     info.downstream_id = msg.recipient_channel;
//   //     break;
//   //   case Dest::Upstream:
//   //     info.upstream_id = msg.recipient_channel;
//   //     break;
//   //   }
//   //   break;
//   }
//   return absl::OkStatus();
// }

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec