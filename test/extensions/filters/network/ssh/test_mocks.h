#pragma once
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/message_handler.h"
#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/buffer/buffer.h"
#include "absl/status/statusor.h"
#pragma clang unsafe_buffer_usage end

#include "gmock/gmock.h" // IWYU pragma: keep

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

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