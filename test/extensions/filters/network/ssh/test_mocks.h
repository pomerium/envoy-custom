#pragma once

#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/kex.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "gmock/gmock.h" // IWYU pragma: keep

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

// template <typename Codec>
// class MockTransport : public TransportBase<Codec> {
// public:
//   MockTransport(Api::Api& api,
//                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config)
//       : TransportBase<Codec>(api, config) {}

//   MOCK_METHOD(absl::StatusOr<size_t>, sendMessageToConnection, (wire::Message&&));
//   MOCK_METHOD(absl::Status, handleMessage, (wire::Message&&));
//   MOCK_METHOD(void, registerMessageHandlers, (MessageDispatcher<wire::Message>&));
//   MOCK_METHOD(void, forward, (wire::Message&&, FrameTags));
//   MOCK_METHOD(void, forwardHeader, (wire::Message&&, FrameTags));
//   MOCK_METHOD(absl::StatusOr<bytes>, signWithHostKey, (bytes_view), (const));
//   MOCK_METHOD(const AuthState&, authState, (), (const));
//   MOCK_METHOD(AuthState&, authState, ());
//   MOCK_METHOD(stream_id_t, streamId, (), (const));
// };

class MockTransportCallbacks : public virtual TransportCallbacks {
public:
  MockTransportCallbacks();
  virtual ~MockTransportCallbacks();

  MOCK_METHOD(absl::StatusOr<size_t>, sendMessageToConnection, (wire::Message&&));
  MOCK_METHOD(void, forward, (wire::Message&&, FrameTags));
  MOCK_METHOD(const bytes&, sessionId, (), (const));
  MOCK_METHOD(absl::StatusOr<bytes>, signWithHostKey, (bytes_view), (const));
  MOCK_METHOD(const AuthState&, authState, (), (const));
  MOCK_METHOD(AuthState&, authState, ());
  MOCK_METHOD(const pomerium::extensions::ssh::CodecConfig&, codecConfig, (), (const));
  MOCK_METHOD(stream_id_t, streamId, (), (const));
  MOCK_METHOD(void, updatePeerExtInfo, (std::optional<wire::ExtInfoMsg>));
  MOCK_METHOD(std::optional<wire::ExtInfoMsg>, outgoingExtInfo, ());
  MOCK_METHOD(std::optional<wire::ExtInfoMsg>, peerExtInfo, (), (const));

  MOCK_METHOD(void, writeToConnection, (Envoy::Buffer::Instance&), (const));
  MOCK_METHOD(absl::StatusOr<size_t>, sendMessageDirect, (wire::Message&&));
  MOCK_METHOD(uint64_t, resetReadSequenceNumber, ());
  MOCK_METHOD(uint64_t, resetWriteSequenceNumber, ());
};

class MockVersionExchangeCallbacks : public VersionExchangeCallbacks {
public:
  MOCK_METHOD(void, onVersionExchangeCompleted, (const bytes&, const bytes&, const bytes&));
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

} // namespace wire