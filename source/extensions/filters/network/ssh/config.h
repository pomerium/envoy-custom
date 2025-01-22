#pragma once

#include "api/extensions/filters/network/ssh/ssh.pb.h"
#include "validate/validate.h"
#include <cerrno>
#include <unistd.h>

#include "source/extensions/filters/network/ssh/server_transport.h"
#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/well_known_names.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

extern "C" {
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
}
namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
class SshCodecFactoryConfig : public CodecFactoryConfig {
public:
  // CodecFactoryConfig
  CodecFactoryPtr
  createCodecFactory(const Protobuf::Message& config,
                     Envoy::Server::Configuration::ServerFactoryContext& context) override;
  std::string name() const override { return "envoy.generic_proxy.codecs.ssh"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<pomerium::extensions::SshCodecConfig>();
  }
};

class SshClientCodec : public ClientCodec {
public:
  SshClientCodec() = default;
  void setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) override {
    (void)callbacks;
  }
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override {
    (void)buffer;
    (void)end_stream;
  }
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override {
    (void)frame;
    (void)ctx;
    return absl::OkStatus();
  }
};

class SshCodecFactory : public CodecFactory {
public:
  SshCodecFactory(Api::Api& api) : api_(api) {}
  ServerCodecPtr createServerCodec() const override {
    return std::make_unique<SshServerCodec>(api_);
  }
  ClientCodecPtr createClientCodec() const override { return std::make_unique<SshClientCodec>(); }

private:
  Api::Api& api_;
};

DECLARE_FACTORY(SshCodecFactoryConfig);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec

// namespace Envoy::Extensions::NetworkFilters::Ssh {

// class SshFilterConfigFactory : public Common::FactoryBase<pomerium::extensions::SshConfig> {
// public:
//   SshFilterConfigFactory() : FactoryBase("envoy.filters.network.ssh") {}

// private:
//   Network::FilterFactoryCb
//   createFilterFactoryFromProtoTyped(const pomerium::extensions::SshConfig& proto_config,
//                                     Server::Configuration::FactoryContext& context) override;
// };

// /* A userdata struct for session. */
// struct session_data_struct {
//   /* Pointer to the channel the session will allocate. */
//   ssh_channel channel;
//   int auth_attempts;
//   int authenticated;
//   int error;
// };

// inline int auth_password(ssh_session session, const char* user, const char* pass, void* userdata)
// {
//   struct session_data_struct* sdata = static_cast<struct session_data_struct*>(userdata);

//   printf("Authenticating user %s pwd %s\n", user, pass);
//   if (strcmp(user, "username") == 0 && strcmp(pass, "password") == 0) {
//     sdata->authenticated = 1;
//     printf("Authenticated\n");
//     return SSH_AUTH_SUCCESS;
//   }
//   if (sdata->auth_attempts >= 3) {
//     printf("Too many authentication tries\n");
//     ssh_disconnect(session);
//     sdata->error = 1;
//     return SSH_AUTH_DENIED;
//   }
//   sdata->auth_attempts++;
//   return SSH_AUTH_DENIED;
// }

// inline ssh_channel channel_open(ssh_session session, void* userdata) {
//   struct session_data_struct* sdata = static_cast<struct session_data_struct*>(userdata);

//   sdata->channel = ssh_channel_new(session);
//   return sdata->channel;
// }

// class SshFilter : public Network::Filter,
//                   public Network::ConnectionCallbacks,
//                   public Logger::Loggable<Logger::Id::filter> {
// public:
//   SshFilter(const pomerium::extensions::SshConfig& proto_config) : config_(proto_config) {
//     ENVOY_LOG(debug, "SshFilter()");
//   }

//   // ReadFilter
//   Network::FilterStatus onData(Buffer::Instance& data, bool) override {
//     read_buffer_.move(data);
//     return Network::FilterStatus::StopIteration;
//   }

//   Network::FilterStatus onNewConnection() override {
//     auto&& conn = read_callbacks_->connection();
//     int fds[2];
//     if (::pipe(fds) != 0) {
//       ENVOY_LOG(error, errorDetails(errno));
//       conn.close(Network::ConnectionCloseType::FlushWrite, "internal server error");
//       return Network::FilterStatus::StopIteration;
//     }
//     read_fd_ = fds[0];
//     write_fd_ = fds[1];
//     conn.addConnectionCallbacks(*this);
//     bind_ = ssh_bind_new();
//     session_ = ssh_new();
//     event_ = ssh_event_new();

//     session_data_ = {.channel = nullptr, .auth_attempts = 0, .authenticated = 0};

//     server_cb_ = ssh_server_callbacks_struct{
//         .userdata = &session_data_,
//         .auth_password_function = auth_password,
//         .channel_open_request_session_function = channel_open,
//     };
//     ssh_callbacks_init(&server_cb_);
//     ssh_event_add_session(event_, session_);

//     if (ssh_handle_key_exchange(session_)) {
//       ENVOY_LOG(error, errorDetails(errno));
//       conn.close(Network::ConnectionCloseType::FlushWrite, ssh_get_error(session_));
//       return Network::FilterStatus::StopIteration;
//     }

//     ssh_set_auth_methods(session_, SSH_AUTH_METHOD_PASSWORD);
//     while (!(session_data_.authenticated && session_data_.channel != nullptr)) {
//       if (session_data_.error)
//         break;
//       auto r = ssh_event_dopoll(event_, -1);
//       if (r == SSH_ERROR) {
//         ENVOY_LOG(error, ssh_get_error(session_));
//         ssh_disconnect(session_);
//         conn.close(Network::ConnectionCloseType::FlushWrite, ssh_get_error(session_));
//       }
//     }
//     ENVOY_LOG(debug, "onNewConnection");
//     return Network::FilterStatus::StopIteration;
//   }
//   void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
//     read_callbacks_ = &callbacks;
//   }
//   void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override {
//     write_callbacks_ = &callbacks;
//   }

//   // WriteFilter
//   Network::FilterStatus onWrite(Buffer::Instance& data, bool) override {
//     write_buffer_.move(data);
//     return Network::FilterStatus::StopIteration;
//   }

//   // ConnectionCallbacks
//   void onEvent(Network::ConnectionEvent event) override {
//     switch (event) {
//     case Network::ConnectionEvent::RemoteClose:
//       [[fallthrough]];
//     case Network::ConnectionEvent::LocalClose:
//       if (read_fd_) {
//         close(read_fd_);
//         close(write_fd_);
//         if (event_) {
//           ssh_event_free(event_);
//         }
//         if (session_) {
//           ssh_free(session_);
//         }
//       }
//       break;
//     case Network::ConnectionEvent::Connected:
//       break;
//     case Network::ConnectionEvent::ConnectedZeroRtt:
//       break;
//     }
//   }
//   void onAboveWriteBufferHighWatermark() override {}
//   void onBelowWriteBufferLowWatermark() override {}

// private:
//   int read_fd_, write_fd_;
//   Buffer::OwnedImpl read_buffer_;
//   Buffer::OwnedImpl write_buffer_;

//   ssh_bind bind_;
//   ssh_session session_;
//   ssh_event event_;
//   ssh_server_callbacks_struct server_cb_;
//   session_data_struct session_data_;

//   pomerium::extensions::SshConfig config_;
//   Network::ReadFilterCallbacks* read_callbacks_{};
//   Network::WriteFilterCallbacks* write_callbacks_{};
// };

// DECLARE_FACTORY(SshFilterConfigFactory);

// } // namespace Envoy::Extensions::NetworkFilters::Ssh

// namespace pomerium::extensions {
// inline bool Validate(const SshConfig&, pgv::ValidationMsg*) { return true; }

// } // namespace pomerium::extensions
