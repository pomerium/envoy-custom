#include "source/extensions/filters/network/ssh/grpc_client_impl.h"
#include "test/extensions/filters/network/ssh/test_mocks.h"
#include "test/mocks/grpc/mocks.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "test/test_common/test_common.h"
#include "test/test_common/utility.h"
#include "api/extensions/filters/network/ssh/ssh.pb.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

class StreamManagementServiceClientTest : public testing::Test {
public:
  void SetUp() {
    client_ = std::make_shared<testing::StrictMock<Grpc::MockAsyncClient>>();
  }

  testing::StrictMock<Grpc::MockAsyncStream> stream_;
  std::shared_ptr<testing::StrictMock<Grpc::MockAsyncClient>> client_;
};

TEST_F(StreamManagementServiceClientTest, Connect) {
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
    .WillOnce(Return(&stream_));
  ClientMessage expectedInitMsg;
  expectedInitMsg.mutable_event()->mutable_downstream_connected()->set_stream_id(1);
  EXPECT_CALL(stream_, sendMessageRaw_(Grpc::ProtoBufferEq(expectedInitMsg), false));
  StreamManagementServiceClient client(client_);
  client.connect(1);
}

TEST_F(StreamManagementServiceClientTest, OnReceiveMessage) {
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
    .WillOnce(Return(&stream_));

  MockStreamMgmtServerMessageHandler handler;
  StreamManagementServiceClient client(client_);
  client.registerHandler(ServerMessage::kAuthResponse, &handler);

  EXPECT_CALL(stream_, sendMessageRaw_);

  ServerMessage msg;
  *msg.mutable_auth_response()->mutable_allow()->mutable_username() = "bar";
  EXPECT_CALL(handler, handleMessage(testing::Pointee(Envoy::ProtoEq(msg))))
    .WillOnce(Return(absl::OkStatus()));

  client.connect(1); // only to ensure client.stream_ is set
  EXPECT_NE(nullptr, &client.stream());
  client.onReceiveMessage(std::make_unique<ServerMessage>(msg));
}

TEST_F(StreamManagementServiceClientTest, OnReceiveMessage_HandlerReturnsError) {
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
    .WillOnce(Return(&stream_));

  MockStreamMgmtServerMessageHandler handler;
  StreamManagementServiceClient client(client_);
  client.registerHandler(ServerMessage::kAuthResponse, &handler);

  ServerMessage msg1;
  msg1.mutable_auth_response();

  EXPECT_CALL(stream_, sendMessageRaw_);
  EXPECT_CALL(handler, handleMessage(_))
    .WillOnce(Return(absl::InvalidArgumentError("test error")));
  client.connect(1);

  client.onReceiveMessage(std::make_unique<ServerMessage>(msg1));
}

TEST_F(StreamManagementServiceClientTest, OnReceiveMessage_HandlerReturnsError_OnRemoteClose) {
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
    .WillOnce(Return(&stream_));

  MockStreamMgmtServerMessageHandler handler;
  StreamManagementServiceClient client(client_);
  client.registerHandler(ServerMessage::kAuthResponse, &handler);

  ServerMessage msg1;
  msg1.mutable_auth_response();

  EXPECT_CALL(stream_, sendMessageRaw_);
  EXPECT_CALL(handler, handleMessage(_))
    .WillOnce(Return(absl::InvalidArgumentError("test error")));
  client.connect(1);

  bool called = false;
  client.setOnRemoteCloseCallback([&](Grpc::Status::GrpcStatus status, std::string err) {
    EXPECT_EQ(Grpc::Status::InvalidArgument, status);
    EXPECT_EQ("test error", err);
    called = true;
  });

  client.onReceiveMessage(std::make_unique<ServerMessage>(msg1));
  EXPECT_TRUE(called);
}

TEST_F(StreamManagementServiceClientTest, OnReceiveMessage_NoRegisteredHandler) {
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
    .WillOnce(Return(&stream_));

  EXPECT_CALL(stream_, sendMessageRaw_);

  StreamManagementServiceClient client(client_);

  ServerMessage msg1;
  msg1.mutable_auth_response();

  client.connect(1);

  client.onReceiveMessage(std::make_unique<ServerMessage>(msg1));
}

TEST_F(StreamManagementServiceClientTest, OnRemoteClose) {
  StreamManagementServiceClient client(client_);

  Envoy::OptRef<Grpc::RawAsyncStreamCallbacks> callbacks_ref{};
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
    .WillOnce(
      Invoke([&](std::string_view, std::string_view, Grpc::RawAsyncStreamCallbacks& callbacks,
                 const Http::AsyncClient::StreamOptions&) {
        callbacks_ref = makeOptRef(callbacks);
        return &stream_;
      }));
  EXPECT_CALL(stream_, sendMessageRaw_);

  bool called = false;
  client.setOnRemoteCloseCallback([&](Grpc::Status::GrpcStatus status, std::string err) {
    EXPECT_EQ(Grpc::Status::InvalidArgument, status);
    EXPECT_EQ("test error", err);
    called = true;
  });
  client.connect(1);
  callbacks_ref->onRemoteClose(Grpc::Status::InvalidArgument, "test error");
  EXPECT_TRUE(called);
}

TEST_F(StreamManagementServiceClientTest, OnRemoteClose_NoCallback) {
  StreamManagementServiceClient client(client_);

  Envoy::OptRef<Grpc::RawAsyncStreamCallbacks> callbacks_ref{};
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
    .WillOnce(
      Invoke([&](std::string_view, std::string_view, Grpc::RawAsyncStreamCallbacks& callbacks,
                 const Http::AsyncClient::StreamOptions&) {
        callbacks_ref = makeOptRef(callbacks);
        return &stream_;
      }));
  EXPECT_CALL(stream_, sendMessageRaw_);
  client.connect(1);
  callbacks_ref->onRemoteClose(Grpc::Status::InvalidArgument, "test error");
}

TEST_F(StreamManagementServiceClientTest, NoopMetadataCallbacks) {
  StreamManagementServiceClient client(client_);
  Envoy::OptRef<Grpc::RawAsyncStreamCallbacks> callbacks_ref{};
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ManageStream", _, _))
    .WillOnce(
      Invoke([&](std::string_view, std::string_view, Grpc::RawAsyncStreamCallbacks& callbacks,
                 const Http::AsyncClient::StreamOptions&) {
        callbacks_ref = makeOptRef(callbacks);
        return &stream_;
      }));

  EXPECT_CALL(stream_, sendMessageRaw_);
  client.connect(1);
  auto headers = Http::RequestHeaderMapImpl::create();
  callbacks_ref->onCreateInitialMetadata(*headers);
  EXPECT_TRUE(headers->empty());

  // these should be no-ops - best we can do is make sure it doesn't crash or something
  callbacks_ref->onReceiveInitialMetadata(Http::ResponseHeaderMapImpl::create());
  callbacks_ref->onReceiveTrailingMetadata(Http::ResponseTrailerMapImpl::create());
}

class ChannelStreamServiceClientTest : public testing::Test {
public:
  void SetUp() {
    client_ = std::make_shared<testing::StrictMock<Grpc::MockAsyncClient>>();
  }

  testing::StrictMock<Grpc::MockAsyncStream> stream_;
  testing::StrictMock<MockChannelStreamCallbacks> callbacks_;
  std::shared_ptr<testing::StrictMock<Grpc::MockAsyncClient>> client_;
};

TEST_F(ChannelStreamServiceClientTest, Start_Metadata) {
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
    .WillOnce(Return(&stream_));
  ChannelStreamServiceClient client(client_);

  envoy::config::core::v3::Metadata md;
  (*md.mutable_filter_metadata())["foo"].mutable_fields()->insert({"bar", ValueUtil::stringValue("baz")});

  ChannelMessage expectedMetadataMsg;
  expectedMetadataMsg.mutable_metadata()->CopyFrom(md);
  EXPECT_CALL(stream_, sendMessageRaw_(Grpc::ProtoBufferEq(expectedMetadataMsg), false));

  auto stream = client.start(&callbacks_, md);
  ASSERT_GT(0, stream.streamInfo().bytesSent());
}

TEST_F(ChannelStreamServiceClientTest, OnReceiveMessage) {
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
    .WillOnce(Return(&stream_));

  ChannelMessage expectedMetadataMsg;
  expectedMetadataMsg.mutable_metadata(); // empty metadata
  EXPECT_CALL(stream_, sendMessageRaw_(Grpc::ProtoBufferEq(expectedMetadataMsg), false)).RetiresOnSaturation();

  ChannelMessage msg1;
  *msg1.mutable_channel_control()->mutable_protocol() = "ssh";
  EXPECT_CALL(callbacks_, onReceiveMessage(testing::Pointee(ProtoEq(msg1))))
    .WillOnce(Return(absl::OkStatus()));

  ChannelStreamServiceClient client(client_);

  client.start(&callbacks_, {});
  client.onReceiveMessage(std::make_unique<ChannelMessage>(msg1));
}

TEST_F(ChannelStreamServiceClientTest, OnReceiveMessage_HandlerReturnsError) {
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
    .WillOnce(Return(&stream_));

  ChannelMessage expectedMetadataMsg;
  expectedMetadataMsg.mutable_metadata(); // empty metadata
  EXPECT_CALL(stream_, sendMessageRaw_(Grpc::ProtoBufferEq(expectedMetadataMsg), false));

  ChannelMessage msg1;
  *msg1.mutable_channel_control()->mutable_protocol() = "ssh";
  EXPECT_CALL(callbacks_, onReceiveMessage(testing::Pointee(ProtoEq(msg1))))
    .WillOnce(Return(absl::InvalidArgumentError("test error")));

  ChannelStreamServiceClient client(client_);

  client.start(&callbacks_, {});

  client.onReceiveMessage(std::make_unique<ChannelMessage>(msg1));
}

TEST_F(ChannelStreamServiceClientTest, OnReceiveMessage_HandlerReturnsError_OnRemoteClose) {
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
    .WillOnce(Return(&stream_));

  ChannelMessage expectedMetadataMsg;
  expectedMetadataMsg.mutable_metadata(); // empty metadata
  EXPECT_CALL(stream_, sendMessageRaw_(Grpc::ProtoBufferEq(expectedMetadataMsg), false));

  ChannelMessage msg1;
  *msg1.mutable_channel_control()->mutable_protocol() = "ssh";
  EXPECT_CALL(callbacks_, onReceiveMessage(testing::Pointee(ProtoEq(msg1))))
    .WillOnce(Return(absl::InvalidArgumentError("test error")));

  ChannelStreamServiceClient client(client_);

  bool called = false;
  client.setOnRemoteCloseCallback([&](Grpc::Status::GrpcStatus status, std::string err) {
    EXPECT_EQ(Grpc::Status::InvalidArgument, status);
    EXPECT_EQ("test error", err);
    called = true;
  });

  client.start(&callbacks_, {});

  client.onReceiveMessage(std::make_unique<ChannelMessage>(msg1));
  EXPECT_TRUE(called);
}

TEST_F(ChannelStreamServiceClientTest, OnRemoteClose) {
  Envoy::OptRef<Grpc::RawAsyncStreamCallbacks> callbacks_ref{};
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
    .WillOnce(
      Invoke([&](std::string_view, std::string_view, Grpc::RawAsyncStreamCallbacks& callbacks,
                 const Http::AsyncClient::StreamOptions&) {
        callbacks_ref = makeOptRef(callbacks);
        return &stream_;
      }));

  ChannelMessage expectedMetadataMsg;
  expectedMetadataMsg.mutable_metadata(); // empty metadata
  EXPECT_CALL(stream_, sendMessageRaw_(Grpc::ProtoBufferEq(expectedMetadataMsg), false));

  ChannelStreamServiceClient client(client_);
  client.start(&callbacks_, {});

  bool called = false;
  client.setOnRemoteCloseCallback([&](Grpc::Status::GrpcStatus status, std::string err) {
    EXPECT_EQ(Grpc::Status::InvalidArgument, status);
    EXPECT_EQ("test error", err);
    called = true;
  });
  callbacks_ref->onRemoteClose(Grpc::Status::InvalidArgument, "test error");
  EXPECT_TRUE(called);
}

TEST_F(ChannelStreamServiceClientTest, OnRemoteClose_NoCallback) {
  Envoy::OptRef<Grpc::RawAsyncStreamCallbacks> callbacks_ref{};
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
    .WillOnce(
      Invoke([&](std::string_view, std::string_view, Grpc::RawAsyncStreamCallbacks& callbacks,
                 const Http::AsyncClient::StreamOptions&) {
        callbacks_ref = makeOptRef(callbacks);
        return &stream_;
      }));

  ChannelMessage expectedMetadataMsg;
  expectedMetadataMsg.mutable_metadata(); // empty metadata
  EXPECT_CALL(stream_, sendMessageRaw_(Grpc::ProtoBufferEq(expectedMetadataMsg), false));

  ChannelStreamServiceClient client(client_);
  client.start(&callbacks_, {});

  callbacks_ref->onRemoteClose(Grpc::Status::InvalidArgument, "test error");
}

TEST_F(ChannelStreamServiceClientTest, NoopMetadataCallbacks) {
  Envoy::OptRef<Grpc::RawAsyncStreamCallbacks> callbacks_ref{};
  IN_SEQUENCE;
  EXPECT_CALL(*client_, startRaw("pomerium.extensions.ssh.StreamManagement", "ServeChannel", _, _))
    .WillOnce(
      Invoke([&](std::string_view, std::string_view, Grpc::RawAsyncStreamCallbacks& callbacks,
                 const Http::AsyncClient::StreamOptions&) {
        callbacks_ref = makeOptRef(callbacks);
        return &stream_;
      }));

  ChannelMessage expectedMetadataMsg;
  expectedMetadataMsg.mutable_metadata(); // empty metadata
  EXPECT_CALL(stream_, sendMessageRaw_(Grpc::ProtoBufferEq(expectedMetadataMsg), false));

  ChannelStreamServiceClient client(client_);
  client.start(&callbacks_, {});

  auto headers = Http::RequestHeaderMapImpl::create();
  callbacks_ref->onCreateInitialMetadata(*headers);
  EXPECT_TRUE(headers->empty());
  callbacks_ref->onReceiveInitialMetadata(Http::ResponseHeaderMapImpl::create());
  callbacks_ref->onReceiveTrailingMetadata(Http::ResponseTrailerMapImpl::create());
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec