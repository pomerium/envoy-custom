#pragma once

#include "source/extensions/filters/network/ssh/transport_base.h"
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

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec