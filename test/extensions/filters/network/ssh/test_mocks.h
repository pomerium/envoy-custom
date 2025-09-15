#pragma once
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/service_connection.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "test/mocks/stats/mocks.h"
#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "gmock/gmock.h" // IWYU pragma: keep

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class MockTransportCallbacks : public virtual TransportCallbacks {
public:
  MockTransportCallbacks();
  virtual ~MockTransportCallbacks();

  MOCK_METHOD(absl::StatusOr<size_t>, sendMessageToConnection, (wire::Message&&));
  MOCK_METHOD(void, forward, (wire::Message&&, FrameTags));
  MOCK_METHOD(const bytes&, sessionId, (), (const));
  MOCK_METHOD(AuthInfo&, authInfo, ());
  MOCK_METHOD(const pomerium::extensions::ssh::CodecConfig&, codecConfig, (), (const));
  MOCK_METHOD(stream_id_t, streamId, (), (const));
  MOCK_METHOD(void, updatePeerExtInfo, (std::optional<wire::ExtInfoMsg>));
  MOCK_METHOD(std::optional<wire::ExtInfoMsg>, outgoingExtInfo, ());
  MOCK_METHOD(std::optional<wire::ExtInfoMsg>, peerExtInfo, (), (const));
  MOCK_METHOD(void, terminate, (absl::Status), (override));
  MOCK_METHOD(Envoy::OptRef<Envoy::Event::Dispatcher>, connectionDispatcher, (), (const override));
  MOCK_METHOD(ChannelIDManager&, channelIdManager, (), (override));
  MOCK_METHOD(Stats::Scope&, statsScope, (), (const));

  MOCK_METHOD(void, writeToConnection, (Envoy::Buffer::Instance&), (const));
  MOCK_METHOD(absl::StatusOr<size_t>, sendMessageDirect, (wire::Message&&));
  MOCK_METHOD(uint64_t, resetReadSequenceNumber, ());
  MOCK_METHOD(uint64_t, resetWriteSequenceNumber, ());

  testing::NiceMock<Stats::MockStore> mock_store_;
  Stats::MockScope& mock_scope_{mock_store_.mockScope()};
};

class MockDownstreamTransportCallbacks : public DownstreamTransportCallbacks,
                                         public MockTransportCallbacks {
public:
  MockDownstreamTransportCallbacks();
  virtual ~MockDownstreamTransportCallbacks();

  MOCK_METHOD(void, initUpstream, (AuthInfoSharedPtr));
  MOCK_METHOD(void, onServiceAuthenticated, (const std::string&));
  MOCK_METHOD(void, sendMgmtClientMessage, (const ClientMessage&));
};

class MockUpstreamTransportCallbacks : public UpstreamTransportCallbacks,
                                       public MockTransportCallbacks {
public:
  MockUpstreamTransportCallbacks();
  virtual ~MockUpstreamTransportCallbacks();
};

class MockVersionExchangeCallbacks : public VersionExchangeCallbacks {
public:
  MOCK_METHOD(void, onVersionExchangeCompleted, (const bytes&, const bytes&, const bytes&));
};

class MockChannel : public Channel {
public:
  MockChannel();
  virtual ~MockChannel();
  MOCK_METHOD(void, Die, ());                                          // NOLINT
  MOCK_METHOD(absl::Status, setChannelCallbacks, (ChannelCallbacks&)); // has a default implementation
  MOCK_METHOD(absl::Status, readMessage, (wire::Message&&));
  MOCK_METHOD(absl::Status, onChannelOpened, (wire::ChannelOpenConfirmationMsg&&));
  MOCK_METHOD(absl::Status, onChannelOpenFailed, (wire::ChannelOpenFailureMsg&&));
};

class MockHijackedChannelCallbacks : public HijackedChannelCallbacks {
public:
  MockHijackedChannelCallbacks();
  virtual ~MockHijackedChannelCallbacks();

  MOCK_METHOD(void, initHandoff, (pomerium::extensions::ssh::SSHChannelControlAction_HandOffUpstream*));
  MOCK_METHOD(void, hijackedChannelFailed, (absl::Status));
};

class MockKexCallbacks : public KexCallbacks {
public:
  MockKexCallbacks();
  virtual ~MockKexCallbacks();

  MOCK_METHOD(void, onVersionExchangeCompleted, (const bytes&, const bytes&, const bytes&));
  MOCK_METHOD(void, onKexStarted, (bool));
  MOCK_METHOD(void, onKexCompleted, (std::shared_ptr<KexResult>, bool));
  MOCK_METHOD(void, onKexInitMsgSent, ());
};

class MockDirectionalPacketCipher : public DirectionalPacketCipher {
public:
  MockDirectionalPacketCipher();
  virtual ~MockDirectionalPacketCipher();

  MOCK_METHOD(absl::StatusOr<size_t>, decryptPacket, (uint32_t, Envoy::Buffer::Instance&, Envoy::Buffer::Instance&));
  MOCK_METHOD(absl::Status, encryptPacket, (uint32_t, Envoy::Buffer::Instance&, Envoy::Buffer::Instance&));
  MOCK_METHOD(size_t, blockSize, (), (const));
  MOCK_METHOD(size_t, aadLen, (), (const));
};

class MockSshMessageHandler : public SshMessageHandler {
public:
  MockSshMessageHandler();
  virtual ~MockSshMessageHandler();

  MOCK_METHOD(absl::Status, handleMessage, (wire::Message&&));
  MOCK_METHOD(void, registerMessageHandlers, (SshMessageDispatcher&));
};

class MockSshMessageMiddleware : public SshMessageMiddleware {
public:
  MockSshMessageMiddleware();
  virtual ~MockSshMessageMiddleware();

  MOCK_METHOD(absl::StatusOr<MiddlewareResult>, interceptMessage, (wire::Message&));
};

class MockStreamMgmtServerMessageHandler : public StreamMgmtServerMessageHandler {
public:
  MockStreamMgmtServerMessageHandler();
  virtual ~MockStreamMgmtServerMessageHandler();

  MOCK_METHOD(absl::Status, handleMessage, (Grpc::ResponsePtr<ServerMessage>&&));
  MOCK_METHOD(void, registerMessageHandlers, (StreamMgmtServerMessageDispatcher&));
};

class MockChannelStreamCallbacks : public ChannelStreamCallbacks {
public:
  MockChannelStreamCallbacks();
  virtual ~MockChannelStreamCallbacks();

  MOCK_METHOD(absl::Status, onReceiveMessage, (Grpc::ResponsePtr<ChannelMessage>&&));
  MOCK_METHOD(void, onStreamClosed, (absl::Status));
};

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

namespace wire {
template <typename T>
constexpr bool holds_alternative(const Message& msg) {
  return msg.message.holds_alternative<T>();
}
template <typename T>
constexpr bool holds_alternative(Message&& msg) {
  return std::move(msg).message.holds_alternative<T>();
}
template <typename T>
constexpr decltype(auto) get(const Message& msg) {
  return msg.message.template get<T>();
}
template <typename T>
constexpr decltype(auto) get(Message&& msg) {
  return std::move(msg).message.template get<T>();
}

template <typename T, typename... Opts>
constexpr bool holds_alternative(const sub_message<Opts...>& msg) {
  return msg.template holds_alternative<T>();
}
template <typename T, typename... Opts>
constexpr bool holds_alternative(sub_message<Opts...>&& msg) {
  return std::move(msg).template holds_alternative<T>();
}
template <typename T, typename... Opts>
constexpr decltype(auto) get(const sub_message<Opts...>& msg) {
  return msg.template get<T>();
}
template <typename T, typename... Opts>
constexpr decltype(auto) get(sub_message<Opts...>&& msg) {
  return std::move(msg).template get<T>();
}

} // namespace wire