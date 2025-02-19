#pragma once

#include "source/extensions/filters/network/generic_proxy/codec_callbacks.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/service.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include <unordered_map>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class UpstreamUserAuthService;
class UpstreamConnectionService;

class SshClientCodec : public virtual Logger::Loggable<Logger::Id::filter>,
                       public ClientCodec,
                       public TransportCallbacks,
                       public KexCallbacks,
                       public SshMessageDispatcher,
                       public SshMessageHandler,
                       public SshMessageMiddleware {
public:
  SshClientCodec(Api::Api& api,
                 std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                 AccessLog::AccessLogFileSharedPtr access_log);

  void setCodecCallbacks(GenericProxy::ClientCodecCallbacks& callbacks) override;
  void decode(Envoy::Buffer::Instance& buffer, bool end_stream) override;
  GenericProxy::EncodingResult encode(const GenericProxy::StreamFrame& frame,
                                      GenericProxy::EncodingContext& ctx) override;

  void setKexResult(std::shared_ptr<kex_result_t> kex_result) override;
  absl::Status handleMessage(SshMsg&& msg) override;
  absl::StatusOr<bytes> signWithHostKey(bytes_view<> in) const override;
  const AuthState& authState() const override;
  AuthState& authState() override;
  void forward(std::unique_ptr<SSHStreamFrame> frame) override;
  const pomerium::extensions::ssh::CodecConfig& codecConfig() const override;

private:
  const connection_state_t& getConnectionState() const override;
  const kex_result_t& getKexResult() const override;
  void writeToConnection(Envoy::Buffer::Instance& buf) const override;
  void registerMessageHandlers(MessageDispatcher<SshMsg>& dispatcher) const override;
  bool interceptMessage(SshMsg& sshMsg) override;
  void doChannelIdRemap(SshMsg& sshMsg, std::unordered_map<uint32_t, uint32_t>& mappings) {
    switch (sshMsg.msg_type()) {
    case SshMessageType::ChannelWindowAdjust: {
      auto& m = dynamic_cast<ChannelWindowAdjustMsg&>(sshMsg);
      m.recipient_channel = mappings.at(m.recipient_channel);
      break;
    }
    case SshMessageType::ChannelData: {
      auto& m = dynamic_cast<ChannelDataMsg&>(sshMsg);
      m.recipient_channel = mappings.at(m.recipient_channel);
      break;
    }
    case SshMessageType::ChannelExtendedData: {
      auto& m = dynamic_cast<ChannelExtendedDataMsg&>(sshMsg);
      m.recipient_channel = mappings.at(m.recipient_channel);
      break;
    }
    case SshMessageType::ChannelEOF: {
      auto& m = dynamic_cast<ChannelEOFMsg&>(sshMsg);
      m.recipient_channel = mappings.at(m.recipient_channel);
      break;
    }
    case SshMessageType::ChannelClose: {
      auto& m = dynamic_cast<ChannelCloseMsg&>(sshMsg);
      m.recipient_channel = mappings.at(m.recipient_channel);
      // mappings.erase(m.recipient_channel);
      break;
    }
    case SshMessageType::ChannelRequest: {
      auto& m = dynamic_cast<ChannelRequestMsg&>(sshMsg);
      m.recipient_channel = mappings.at(m.recipient_channel);
      break;
    }
    case SshMessageType::ChannelSuccess: {
      auto& m = dynamic_cast<ChannelSuccessMsg&>(sshMsg);
      m.recipient_channel = mappings.at(m.recipient_channel);
      break;
    }
    case SshMessageType::ChannelFailure: {
      auto& m = dynamic_cast<ChannelFailureMsg&>(sshMsg);
      m.recipient_channel = mappings.at(m.recipient_channel);
      break;
    }
    default:
      break;
    }
  }

  GenericProxy::ClientCodecCallbacks* callbacks_{};
  bool version_exchange_done_{};
  bool first_kex_done_{};
  std::unique_ptr<VersionExchanger> version_exchanger_;
  std::shared_ptr<kex_result_t> kex_result_;
  Api::Api& api_;
  std::unique_ptr<Kex> kex_;
  std::unique_ptr<connection_state_t> connection_state_;
  AuthStateSharedPtr downstream_state_;
  std::unique_ptr<UpstreamUserAuthService> user_auth_svc_;
  std::unique_ptr<UpstreamConnectionService> connection_svc_;
  std::map<std::string, Service*> services_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;
  AccessLog::AccessLogFileSharedPtr access_log_;

  bool channel_id_remap_enabled_{false};

  // translates upstream channel ids from {the id the downstream thinks the upstream has} -> {the id the upstream actually has}
  std::unordered_map<uint32_t, uint32_t> channel_id_mappings_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec