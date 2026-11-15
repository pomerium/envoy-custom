#pragma once

#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/fxp.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class FxpStreamDecoder : public SshMessageHandler,
                         public MessageDispatcher<wire::fxp::Message> {
public:
  void registerMessageHandlers(SshMessageDispatcher& dispatcher) override {
    dispatcher.registerHandler(wire::SshMessageType::ChannelData, this);
  }

  absl::Status handleMessage(wire::Message&& msg) override {
    auto& channelDataMsg = msg.message.get<wire::ChannelDataMsg>();
    buffer_.add(channelDataMsg.data->data(), channelDataMsg.data->size());
    return onReadyRead();
  }

private:
  absl::Status onReadyRead() {
    while (buffer_.length() >= 4) {
      auto len = buffer_.peekBEInt<uint32_t>();
      if (len == 0) [[unlikely]] {
        return absl::InvalidArgumentError("invalid packet format: read zero-length message");
      }
      if (buffer_.length() >= 4 + len) {
        // there is enough data to read a full message
        buffer_.drain(4); // drain the length
        wire::fxp::Message msg;
        if (auto n = msg.decode(buffer_, len); !n.ok()) {
          return n.status();
        }
        if (auto stat = dispatch(std::move(msg)); !stat.ok()) {
          return stat;
        }
      } else {
        // incomplete packet, wait for more data
        break;
      }
    }
    return absl::OkStatus();
  }

  Envoy::Buffer::OwnedImpl buffer_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec