#pragma once

#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/service_userauth.h"
#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/openssh.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "test/extensions/filters/network/ssh/ssh_connection_driver.h"
#include "test/extensions/filters/network/ssh/ssh_integration_common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class SshFakeUpstreamHandlerCodecCallbacks {
public:
  virtual ~SshFakeUpstreamHandlerCodecCallbacks() = default;
  virtual void onDecodingFailure(absl::string_view reason = {}) PURE;
  virtual void writeToConnection(Buffer::Instance& buffer) PURE;
};

class SshFakeUpstreamHandlerCodec {
public:
  virtual ~SshFakeUpstreamHandlerCodec() = default;
  virtual void setCodecCallbacks(SshFakeUpstreamHandlerCodecCallbacks&) PURE;
  virtual void decode(Envoy::Buffer::Instance& buffer, bool end_stream) PURE;
};

template <>
struct codec_traits<SshFakeUpstreamHandlerCodec> {
  using callbacks_type = SshFakeUpstreamHandlerCodecCallbacks;
  static constexpr DirectionTags direction_read = clientKeys;
  static constexpr DirectionTags direction_write = serverKeys;
  static constexpr auto kex_mode = KexMode::Server;
  static constexpr std::string_view name = "server";
  static constexpr auto version_exchange_mode = VersionExchangeMode::Server;
};

class FakeUpstreamChannel : public Channel {
public:
  FakeUpstreamChannel(ChannelMsgHandlerFunc msg_handler)
      : msg_handler_(std::move(msg_handler)) {}

  absl::Status setChannelCallbacks(ChannelCallbacks& callbacks) override {
    RETURN_IF_NOT_OK(Channel::setChannelCallbacks(callbacks));
    callbacks_->sendMessageLocal(
      wire::ChannelOpenConfirmationMsg{
        .recipient_channel = callbacks_->channelId(),
        .sender_channel = callbacks_->channelId(),
        .initial_window_size = wire::ChannelWindowSize,
        .max_packet_size = wire::ChannelMaxPacketSize,
      });
    return absl::OkStatus();
  }
  absl::Status readMessage(wire::ChannelMessage&& msg) override {
    return msg_handler_(std::move(msg), *callbacks_);
  }

  ChannelMsgHandlerFunc msg_handler_;
};

class SshFakeUpstreamHandler : public SecretsProviderImpl,
                               public FakeSshUpstreamCallbacks,
                               public Envoy::Event::DispatcherThreadDeletable,
                               public TransportBase<SshFakeUpstreamHandlerCodec> {
public:
  SshFakeUpstreamHandler(Server::Configuration::ServerFactoryContext& context,
                         std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                         std::shared_ptr<SshFakeUpstreamHandlerOpts> opts);

  class CodecCallbacks : public SshFakeUpstreamHandlerCodecCallbacks {
  public:
    explicit CodecCallbacks(Network::Connection& connection);
    void onDecodingFailure(absl::string_view reason = {}) override;
    void writeToConnection(Buffer::Instance& buffer) override;

    Network::Connection& connection_;
  };

  class ReadFilter : public Envoy::Network::ReadFilter,
                     public std::enable_shared_from_this<ReadFilter> {
  public:
    ReadFilter(SshFakeUpstreamHandler& parent)
        : parent_(parent) {}
    // Envoy::Network::ReadFilter
    Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
    Network::FilterStatus onNewConnection() override;
    void initializeReadFilterCallbacks(Envoy::Network::ReadFilterCallbacks& callbacks) override;

  private:
    Envoy::Network::ReadFilterCallbacks* read_filter_callbacks_{nullptr};
    SshFakeUpstreamHandler& parent_;
  };

  void onNewConnection(Network::Connection& connection) override {
    connection_ = makeOptRef(connection);
    dispatcher_ = makeOptRef(connection.dispatcher());
    codec_callbacks_ = std::make_unique<CodecCallbacks>(connection);
    setCodecCallbacks(*codec_callbacks_);
    connection_service_ = std::make_unique<FakeUpstreamConnectionService>(*this);
    user_auth_service_ = std::make_unique<FakeUpstreamUserAuthService>(*this);
    read_filter_ = std::make_shared<ReadFilter>(*this);
    connection.addReadFilter(read_filter_);
  }

protected:
  class FakeUpstreamConnectionService : public ConnectionService {
  public:
    FakeUpstreamConnectionService(SshFakeUpstreamHandler& parent);
    absl::Status handleMessage(wire::Message&& msg) override;

  private:
    SshFakeUpstreamHandler& parent_;
  };

  class FakeUpstreamUserAuthService : public UserAuthService {
  public:
    FakeUpstreamUserAuthService(SshFakeUpstreamHandler& parent);
    void registerMessageHandlers(SshMessageDispatcher& dispatcher);
    absl::Status handleMessage(wire::Message&& msg);

  private:
    SshFakeUpstreamHandler& parent_;
  };

  Envoy::OptRef<Envoy::Event::Dispatcher> connectionDispatcher() const override {
    return dispatcher_;
  }

  // TransportBase
  void forward(wire::Message&&, FrameTags = EffectiveCommon) override {
    PANIC("unused");
  }
  AuthInfo& authInfo() override {
    PANIC("unused");
  }

  ChannelIDManager& channelIdManager() override {
    return channel_id_manager_;
  }

  stream_id_t streamId() const override {
    return 42; // unused, except in logs
  }

  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;
  absl::Status handleMessage(wire::Message&& msg) override;

private:
  ChannelIDManager channel_id_manager_{100}; // order is important here
  MessageDispatcher<wire::Message>* msg_dispatcher_{};
  std::shared_ptr<SshFakeUpstreamHandlerOpts> opts_;
  std::unique_ptr<CodecCallbacks> codec_callbacks_;
  std::shared_ptr<ReadFilter> read_filter_;
  Envoy::OptRef<Network::Connection> connection_;
  Envoy::OptRef<Envoy::Event::Dispatcher> dispatcher_;
  std::unique_ptr<FakeUpstreamUserAuthService> user_auth_service_;
  std::unique_ptr<FakeUpstreamConnectionService> connection_service_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec