#pragma once

#include "source/extensions/filters/network/ssh/channel.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "gtest/gtest-assertion-result.h"
#include "source/common/grpc/codec.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"

#include <coroutine>
#include <exception>
#include <utility>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class SecretsProviderImpl : public SecretsProvider {
public:
  std::vector<openssh::SSHKeySharedPtr> hostKeys() const override {
    return {host_key_};
  };

  openssh::SSHKeySharedPtr userCaKey() const override {
    return user_ca_key_;
  };

  openssh::SSHKeySharedPtr host_key_ = *openssh::SSHKey::generate(KEY_ED25519, 256);
  openssh::SSHKeySharedPtr user_ca_key_ = *openssh::SSHKey::generate(KEY_ED25519, 256);
};

// These shims allow us to skip including fake_upstream.h in this file, since it is massive
// and adds like 90 seconds to the compile time of any TU that includes it. Modifications to
// just the connection driver should be much quicker to build.

class FakeStreamShim {
public:
  virtual ~FakeStreamShim() = default;
  virtual void startGrpcStream() PURE;
  virtual testing::AssertionResult
  waitForGrpcMessage(Envoy::Event::Dispatcher& client_dispatcher, Protobuf::Message& message,
                     std::chrono::milliseconds timeout) PURE;

  virtual void sendGrpcMessage(const Protobuf::Message& message) PURE;
};

class FakeHttpConnectionShim {
public:
  virtual ~FakeHttpConnectionShim() = default;
  [[nodiscard]]
  virtual testing::AssertionResult waitForNewStream(
    Envoy::Event::Dispatcher& client_dispatcher, std::unique_ptr<FakeStreamShim>& stream,
    std::chrono::milliseconds timeout) PURE;
  [[nodiscard]]
  virtual testing::AssertionResult close(Network::ConnectionCloseType close_type, std::chrono::milliseconds timeout) PURE;
  [[nodiscard]]
  virtual testing::AssertionResult waitForDisconnect(std::chrono::milliseconds timeout) PURE;
};

using ChannelMsgHandlerFunc = absl::AnyInvocable<absl::Status(wire::ChannelMessage&&, ChannelCallbacks&)>;
using OnChannelDestroyedFunc = absl::AnyInvocable<void()>;

class FakeUpstreamHandlerApi {
public:
  virtual ~FakeUpstreamHandlerApi() = default;
  virtual void closeConnection(Network::ConnectionCloseType) PURE;
};

class FakeSshUpstreamHandlerApi : public FakeUpstreamHandlerApi {
public:
  virtual ~FakeSshUpstreamHandlerApi() = default;
  virtual void requestChannelOpen() PURE;
};

struct stream_promise;

struct stream_coroutine : std::coroutine_handle<stream_promise> {
  using promise_type = stream_promise;
};

class UntypedFakeGrpcStreamApi {
public:
  virtual ~UntypedFakeGrpcStreamApi() = default;
  virtual absl::Status RecvMsg(google::protobuf::Message&) PURE;
  virtual void SendMsg(const google::protobuf::Message& msg) PURE;
  virtual size_t BufferedFrameCount() const PURE;
  virtual absl::Status Err() const PURE;

  virtual const Http::RequestHeaderMap& Headers() const PURE;
  virtual const Http::MetadataMap& Metadata() const PURE;
  virtual Envoy::OptRef<const Http::RequestTrailerMap> Trailers() const PURE;
  virtual void SetHeaders(Http::ResponseHeaderMapPtr) PURE;
  virtual void SetTrailers(Http::ResponseTrailerMapPtr) PURE;
  virtual void SendHeaders() PURE;

  virtual void ReturnValue(absl::Status) PURE;
};

class FakeGrpcStream {
  friend class UntypedFakeGrpcStream;

  struct recv_awaiter {
    recv_awaiter(FakeGrpcStream& parent, google::protobuf::Message& message)
        : parent_(parent),
          message_(message) {}

    bool await_ready() noexcept {
      return parent_.parent_.BufferedFrameCount() > 0 || !parent_.parent_.Err().ok();
    }

    void await_suspend(std::coroutine_handle<stream_promise>) noexcept {}

    absl::Status await_resume() noexcept {
      if (parent_.parent_.BufferedFrameCount() > 0) {
        return parent_.parent_.RecvMsg(message_);
      }
      auto err = parent_.parent_.Err();
      ASSERT(!err.ok());
      return err;
    }

    FakeGrpcStream& parent_;
    google::protobuf::Message& message_;
  };

public:
  recv_awaiter RecvMsg(google::protobuf::Message& message) {
    return {*this, message};
  }

  void SendMsg(const google::protobuf::Message& msg) { parent_.SendMsg(msg); }
  const Http::RequestHeaderMap& Headers() const { return parent_.Headers(); }
  const Http::MetadataMap& Metadata() const { return parent_.Metadata(); }
  Envoy::OptRef<const Http::RequestTrailerMap> Trailers() const { return parent_.Trailers(); }

  void SetHeaders(Http::ResponseHeaderMapPtr headers) {
    parent_.SetHeaders(std::move(headers));
  }

  void SetTrailers(Http::ResponseTrailerMapPtr trailers) {
    parent_.SetTrailers(std::move(trailers));
  }

  void SendHeaders() {
    parent_.SendHeaders();
  }

private:
  FakeGrpcStream(UntypedFakeGrpcStreamApi& parent)
      : parent_(parent) {}

  UntypedFakeGrpcStreamApi& parent_;
};

struct stream_promise {
  stream_promise() = delete;
  stream_promise(FakeGrpcStream parent)
      : parent_(parent) {}

  stream_coroutine get_return_object() {
    return {stream_coroutine::from_promise(*this)};
  }

  std::suspend_always initial_suspend() noexcept { return {}; }
  std::suspend_always final_suspend() noexcept { return {}; }

  void unhandled_exception() {
    exception_ = std::current_exception();
  }

  void return_value(absl::Status status) {
    status_.emplace(std::move(status));
  }

  std::optional<absl::Status> status_;
  std::exception_ptr exception_;
  FakeGrpcStream parent_;
};

static_assert(requires { typename std::coroutine_traits<stream_coroutine, decltype([](FakeGrpcStream) -> stream_coroutine { co_return absl::OkStatus(); })&>::promise_type; });

class UntypedFakeGrpcStream : public UntypedFakeGrpcStreamApi,
                              public Http::RequestDecoder,
                              public Http::StreamCallbacks,
                              public Envoy::LinkedObject<UntypedFakeGrpcStream>,
                              public Envoy::Logger::Loggable<Envoy::Logger::Id::testing> {
public:
  UntypedFakeGrpcStream(Http::ResponseEncoder& response_encoder,
                        absl::AnyInvocable<stream_coroutine(FakeGrpcStream)>& coroutine_fn,
                        absl::AnyInvocable<void(UntypedFakeGrpcStream*)> on_destroy);

  // UntypedFakeGrpcStreamApi
  absl::Status RecvMsg(google::protobuf::Message& message) override;
  void SendMsg(const google::protobuf::Message& msg) override;
  size_t BufferedFrameCount() const override;
  absl::Status Err() const override;
  const Http::RequestHeaderMap& Headers() const override;
  const Http::MetadataMap& Metadata() const override;
  Envoy::OptRef<const Http::RequestTrailerMap> Trailers() const override;
  void SetHeaders(Http::ResponseHeaderMapPtr headers) override;
  void SetTrailers(Http::ResponseTrailerMapPtr trailers) override;
  void SendHeaders() override;
  void ReturnValue(absl::Status err) override;

private:
  // Http::RequestDecoder
  void decodeHeaders(Http::RequestHeaderMapSharedPtr&& headers, bool end_stream) override;
  void decodeTrailers(Http::RequestTrailerMapPtr&& trailers) override;
  void sendLocalReply(Http::Code code, absl::string_view body, const std::function<void(Http::ResponseHeaderMap&)>& /*modify_headers*/,
                      const absl::optional<Grpc::Status::GrpcStatus> grpc_status, absl::string_view /*details*/) override;
  StreamInfo::StreamInfo& streamInfo() override;
  AccessLog::InstanceSharedPtrVector accessLogHandlers() override;
  Http::RequestDecoderHandlePtr getRequestDecoderHandle() override;
  void decodeData(Buffer::Instance& data, bool end_stream) override;
  void decodeMetadata(Http::MetadataMapPtr&& metadata_map) override;

  // Http::StreamCallbacks

  /**
   * Fires when a stream has been remote reset.
   * @param reason supplies the reset reason.
   * @param transport_failure_reason supplies underlying transport failure reason.
   */
  virtual void onResetStream(Http::StreamResetReason reason,
                             absl::string_view transport_failure_reason) override;
  virtual void onAboveWriteBufferHighWatermark() override {}
  virtual void onBelowWriteBufferLowWatermark() override {}

  void resumeHandler();

  class RequestDecoderHandle : public Http::RequestDecoderHandle {
  public:
    explicit RequestDecoderHandle(UntypedFakeGrpcStream& stream) : stream_(stream) {}
    OptRef<RequestDecoder> get() override { return stream_; }

  private:
    UntypedFakeGrpcStream& stream_;
  };

  Http::ResponseEncoder& response_encoder_;
  absl::AnyInvocable<void(UntypedFakeGrpcStream*)> on_destroy_;
  Envoy::Grpc::Decoder grpc_decoder_;
  std::vector<Grpc::Frame> decoded_grpc_frames_;
  std::shared_ptr<StreamInfo::StreamInfo> stream_info_; // currently unused
  AccessLog::InstanceSharedPtrVector access_log_handlers_;

  bool stream_started_{};
  absl::Status stream_error_ = absl::OkStatus();
  Http::RequestHeaderMapSharedPtr headers_;
  Http::MetadataMap metadata_map_;
  Http::RequestTrailerMapPtr trailers_;
  Http::ResponseHeaderMapPtr response_headers_;
  Http::ResponseTrailerMapPtr response_trailers_;

  std::optional<stream_coroutine> coroutine_;
};

struct SshFakeUpstreamHandlerOpts {
  std::function<bool(uint32_t)> should_accept_channel = [](uint32_t) { return true; };
  absl::AnyInvocable<ChannelMsgHandlerFunc(wire::ChannelOpenMsg&)> on_channel_open_request;
  absl::AnyInvocable<ChannelMsgHandlerFunc(wire::ChannelOpenConfirmationMsg&)> on_channel_accepted;
  absl::AnyInvocable<ChannelMsgHandlerFunc(wire::ChannelOpenFailureMsg&)> on_channel_rejected;
  absl::AnyInvocable<OnChannelDestroyedFunc(uint32_t, Envoy::Event::Dispatcher&, ChannelCallbacks&)> on_channel_created;
  absl::AnyInvocable<void(const wire::DisconnectMsg&)> on_disconnect;
  absl::AnyInvocable<void(FakeSshUpstreamHandlerApi&)> set_upstream_api;
};

struct UntypedGrpcFakeUpstreamHandlerOpts {
  absl::AnyInvocable<stream_coroutine(FakeGrpcStream)> handle_stream;
  absl::AnyInvocable<void(FakeUpstreamHandlerApi&)> set_upstream_api;
};

class FakeUpstreamShim {
public:
  virtual ~FakeUpstreamShim() = default;

  [[nodiscard]]
  virtual testing::AssertionResult waitForHttpConnection(Envoy::Event::Dispatcher& client_dispatcher,
                                                         std::unique_ptr<FakeHttpConnectionShim>& connection,
                                                         std::chrono::milliseconds timeout) PURE;

  [[nodiscard]]
  virtual testing::AssertionResult listenForSshConnection(std::shared_ptr<SshFakeUpstreamHandlerOpts> opts,
                                                          Server::Configuration::ServerFactoryContext& ctx) PURE;

  [[nodiscard]]
  virtual testing::AssertionResult listenForGrpcConnection(std::shared_ptr<UntypedGrpcFakeUpstreamHandlerOpts> opts,
                                                           Server::Configuration::ServerFactoryContext& ctx) PURE;

  virtual Http::Http2::CodecStats& http2CodecStats() PURE;
  virtual const envoy::config::core::v3::Http2ProtocolOptions& http2Options() PURE;
  virtual Network::Address::InstanceConstSharedPtr localAddress() const PURE;

  virtual void cleanup(absl::Duration timeout) PURE;
};

class FakeUpstreamHandlerCallbacks {
public:
  virtual ~FakeUpstreamHandlerCallbacks() = default;
  virtual void onNewConnection(Envoy::Network::Connection& connection) PURE;
};

using UntypedFakeGrpcStreamHandlerFunc = absl::AnyInvocable<stream_coroutine(FakeGrpcStream)>;

struct AddFakeUpstreamOpts {
  std::function<void(Network::ListenerFilterManager&)> create_listener_filter_chain;
};

class AddExtraFakeUpstreamApi {
public:
  virtual ~AddExtraFakeUpstreamApi() = default;
  virtual std::unique_ptr<FakeUpstreamShim> addExtraFakeUpstream(Http::CodecType type, const std::string& name, AddFakeUpstreamOpts opts = {}) PURE;
};

// Wrapper for static ConfigHelper methods. These are implemented in ssh_integration_test.cc.
// Used to avoid the dependency on ConfigHelper in conformance test implementations.
class ConfigHelperShim {
public:
  virtual envoy::config::cluster::v3::Cluster buildStaticCluster(const std::string& name, int port, const std::string& address,
                                                                 const envoy::config::cluster::v3::Cluster::LbPolicy lb_policy =
                                                                   envoy::config::cluster::v3::Cluster::ROUND_ROBIN) PURE;
  virtual void setHttp2(envoy::config::cluster::v3::Cluster& cluster) PURE;
  virtual void setHttp2WithMaxConcurrentStreams(envoy::config::cluster::v3::Cluster& cluster,
                                                uint32_t max_concurrent_streams) PURE;
  virtual bool loadHttpConnectionManager(envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) PURE;
  virtual void storeHttpConnectionManager(const envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) PURE;
};

class SshIntegrationTestApi {
public:
  virtual std::string localhost() const PURE;
  virtual testing::AssertionResult listenForSshConnection(SshFakeUpstreamHandlerOpts&& opts, size_t upstream_index = 0) PURE;
  virtual testing::AssertionResult listenForGrpcConnection(UntypedGrpcFakeUpstreamHandlerOpts&& opts, FakeUpstreamShim& fake_upstream) PURE;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec