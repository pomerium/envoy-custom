#pragma once

#include "source/extensions/filters/network/ssh/transport_base.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include "test/extensions/filters/network/generic_proxy/mocks/codec.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "gmock/gmock.h" // IWYU pragma: keep

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

template <typename Codec>
class MockTransport : public TransportBase<Codec> {
public:
  MockTransport(Api::Api& api,
                std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config)
      : TransportBase<Codec>(api, config) {}

  MOCK_METHOD(absl::StatusOr<size_t>, sendMessageToConnection, (wire::Message&&));
  MOCK_METHOD(absl::Status, handleMessage, (wire::Message&&));
  MOCK_METHOD(void, registerMessageHandlers, (MessageDispatcher<wire::Message>&));
  MOCK_METHOD(void, forward, (wire::Message&&, FrameTags));
  MOCK_METHOD(void, forwardHeader, (wire::Message&&, FrameTags));
  MOCK_METHOD(absl::StatusOr<bytes>, signWithHostKey, (bytes_view), (const));
  MOCK_METHOD(const AuthState&, authState, (), (const));
  MOCK_METHOD(AuthState&, authState, ());
  MOCK_METHOD(stream_id_t, streamId, (), (const));
};

class MockTransportCallbacks : public TransportCallbacks {
public:
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

class MockKexCallbacks : public KexCallbacks {
public:
  MOCK_METHOD(void, onKexStarted, (bool));
  MOCK_METHOD(void, onKexCompleted, (std::shared_ptr<KexResult>, bool));
  MOCK_METHOD(void, onKexInitMsgSent, ());
};

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec