#pragma once

#include <concepts>

#include "source/common/math.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/kex_alg_curve25519.h"
#include "source/extensions/filters/network/ssh/packet_cipher_aead.h"
#include "source/extensions/filters/network/ssh/packet_cipher_etm.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

template <typename T>
struct codec_traits;

template <typename T>
  requires std::derived_from<T, ServerCodec>
struct codec_traits<T> {
  using callbacks_type = ServerCodecCallbacks;
  static constexpr DirectionTags direction_read = clientKeys;
  static constexpr DirectionTags direction_write = serverKeys;
  static constexpr KexMode kex_mode = KexMode::Server;
  static constexpr std::string_view name = "server";
};

template <typename T>
  requires std::derived_from<T, ClientCodec>
struct codec_traits<T> {
  using callbacks_type = ClientCodecCallbacks;
  static constexpr DirectionTags direction_read = serverKeys;
  static constexpr DirectionTags direction_write = clientKeys;
  static constexpr KexMode kex_mode = KexMode::Client;
  static constexpr std::string_view name = "client";
};

// RFC4344 § 3.1 states:
//  SSH implementations SHOULD also attempt to rekey before receiving
//  more than 2**32 packets since the last rekey operation.  The
//  preferred way to do this is to rekey after receiving more than 2**31
//  packets since the last rekey operation.
//
// Note that because we require strict key exchange, the sequence number is used to determine how
// many packets have been sent/received.
static constexpr uint32_t seqnum_rekey_limit = 1 << 31;

template <typename Codec>
class TransportBase : public Codec,
                      public KexCallbacks,
                      public SshMessageDispatcher,
                      public SshMessageHandler,
                      public virtual TransportCallbacks,
                      public virtual Logger::Loggable<Logger::Id::filter> {
public:
  TransportBase(Api::Api& api,
                std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config)
      : api_(api), config_(config) {
    algorithm_factories_.registerType<Curve25519Sha256KexAlgorithmFactory>();
    cipher_factories_.registerType<Chacha20Poly1305CipherFactory>();
    cipher_factories_.registerType<AESGCM128CipherFactory>();
    cipher_factories_.registerType<AESGCM256CipherFactory>();
    cipher_factories_.registerType<AES128CTRCipherFactory>();
    cipher_factories_.registerType<AES192CTRCipherFactory>();
    cipher_factories_.registerType<AES256CTRCipherFactory>();
  }
  using Callbacks = codec_traits<Codec>::callbacks_type;

  void setCodecCallbacks(Callbacks& callbacks) override {
    this->callbacks_ = &callbacks;
    kex_ = std::make_unique<Kex>(*this, *this, algorithm_factories_, cipher_factories_, codec_traits<Codec>::kex_mode);
    kex_->registerMessageHandlers(*this);
    version_exchanger_ = std::make_unique<VersionExchanger>(*this, *kex_);

    cipher_state_.cipher = std::make_unique<PacketCipher>(std::make_unique<NoCipher>(), std::make_unique<NoCipher>());
    cipher_state_.seq_read = 0;
    cipher_state_.seq_write = 0;
    cipher_state_.read_bytes_remaining = cipher_state_.cipher->rekeyAfterBytes(openssh::CipherMode::Read);
    cipher_state_.write_bytes_remaining = cipher_state_.cipher->rekeyAfterBytes(openssh::CipherMode::Write);
  }

  void decode(Envoy::Buffer::Instance& buffer, bool /*end_stream*/) override {
    while (buffer.length() > 0) {
      if (!version_exchange_done_) {
        if (!version_exchanger_->versionRead()) {
          auto stat = version_exchanger_->readVersion(buffer);
          if (!stat.ok()) {
            onDecodingFailure(stat);
            return;
          }
        }
        if (!version_exchanger_->versionWritten()) {
          auto n = version_exchanger_->writeVersion(server_version_);
          if (!n.ok()) {
            onDecodingFailure(n.status());
            return;
          }
        }
        version_exchange_done_ = true;
        continue;
      }

      Envoy::Buffer::OwnedImpl dec;
      auto bytes_read = cipher_state_.cipher->decryptPacket(cipher_state_.seq_read, dec, buffer);
      if (!bytes_read.ok()) {
        onDecodingFailure(statusf("failed to decrypt packet: {}", bytes_read.status()));
        return;
      } else if (*bytes_read == 0) {
        // note: sequence number not increased
        ENVOY_LOG(debug, "received incomplete packet; waiting for more data");
        return;
      }
      auto next_read_seq = ++cipher_state_.seq_read;

      wire::Message msg;
      auto packet_len = wire::decodePacket(dec, msg);
      if (!packet_len.ok()) {
        onDecodingFailure(statusf("failed to decode packet: {}", packet_len.status()));
        return;
      }
      ENVOY_LOG(trace, "received message: size: {}, type: {}", *packet_len, msg.msg_type());
      if (auto err = onMessageDecoded(std::move(msg)); !err.ok()) {
        onDecodingFailure(err);
        return;
      }

      cipher_state_.read_bytes_remaining = sub_sat(cipher_state_.read_bytes_remaining,
                                                   static_cast<uint64_t>(*bytes_read));
      if (!cipher_state_.pending_key_exchange &&
          (cipher_state_.read_bytes_remaining == 0 || next_read_seq > seqnum_rekey_limit)) {
        ENVOY_LOG(debug, "ssh [{}]: read rekey threshold was reached, initiating key re-exchange (bytes remaining: {}; packets sent: {})",
                  codec_traits<Codec>::name,
                  cipher_state_.read_bytes_remaining, next_read_seq);
        auto stat = kex_->initiateKex();
        if (!stat.ok()) {
          onDecodingFailure(statusf("failed to initiate rekey: {}", stat));
        }
      }
    }
  }

  const bytes& sessionId() const final {
    return kex_result_->session_id;
  }
  const pomerium::extensions::ssh::CodecConfig& codecConfig() const final { return *config_; }

  void writeToConnection(Envoy::Buffer::Instance& buf) const final {
    return callbacks_->writeToConnection(buf);
  }

  void updatePeerExtInfo(std::optional<wire::ExtInfoMsg> msg) override {
    peer_ext_info_ = std::move(msg);
  }

  std::optional<wire::ExtInfoMsg> outgoingExtInfo() final {
    if (outgoing_ext_info_.has_value()) {
      std::optional<wire::ExtInfoMsg> out;
      outgoing_ext_info_.swap(out);
      return out;
    }
    return {};
  }

  std::optional<wire::ExtInfoMsg> peerExtInfo() const final {
    return {peer_ext_info_};
  }

  absl::StatusOr<size_t> sendMessageToConnection(wire::Message&& msg) override {
    if (!cipher_state_.pending_key_exchange) [[likely]] {
      return sendMessageDirect(std::move(msg));
    } else {
      ENVOY_LOG(debug, "queueing message due to pending key exchange: {}", msg.msg_type());
      enqueueMessage(std::move(msg));
      return 0uz;
    }
  }

  void onKexInitMsgSent() final {
    cipher_state_.pending_key_exchange = true;
  }

protected:
  virtual absl::Status onMessageDecoded(wire::Message&& msg) {
    return dispatch(std::move(msg));
  }

  void onKexStarted(bool initial_kex) override {
    if (initial_kex) {
      ENVOY_LOG(debug, "ssh [{}]: starting initial key exchange", codec_traits<Codec>::name);
    } else {
      ENVOY_LOG(debug, "ssh [{}]: starting key re-exchange", codec_traits<Codec>::name);
    }
  }

  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override {
    ASSERT(cipher_state_.pending_key_exchange);
    kex_result_ = kex_result;

    cipher_state_.cipher = kex_->makePacketCipher(codec_traits<Codec>::direction_read,
                                                  codec_traits<Codec>::direction_write,
                                                  codec_traits<Codec>::kex_mode,
                                                  kex_result.get());
    if (config_->has_rekey_threshold()) {
      cipher_state_.read_bytes_remaining = std::max<uint64_t>(256, config_->rekey_threshold());
      cipher_state_.write_bytes_remaining = std::max<uint64_t>(256, config_->rekey_threshold());
      ENVOY_LOG(debug, "ssh [{}]: new read bytes remaining: {}", codec_traits<Codec>::name, cipher_state_.read_bytes_remaining);
      ENVOY_LOG(debug, "ssh [{}]: new write bytes remaining: {}", codec_traits<Codec>::name, cipher_state_.write_bytes_remaining);

    } else {
      cipher_state_.read_bytes_remaining = cipher_state_.cipher->rekeyAfterBytes(openssh::CipherMode::Read);
      cipher_state_.write_bytes_remaining = cipher_state_.cipher->rekeyAfterBytes(openssh::CipherMode::Write);
    }

    cipher_state_.pending_key_exchange = false;

    if (initial_kex) {
      ENVOY_LOG(debug, "ssh [{}]: initial key exchange completed", codec_traits<Codec>::name);
      this->registerMessageHandlers(*static_cast<SshMessageDispatcher*>(this));
    } else {
      ENVOY_LOG(debug, "ssh [{}]: key re-exchange completed", codec_traits<Codec>::name);

      if (!pending_messages_.empty()) {
        ENVOY_LOG(debug, "ssh [{}]: sending {} messages queued during key re-exchange",
                  codec_traits<Codec>::name, pending_messages_.size());
        while (!pending_messages_.empty() && !cipher_state_.pending_key_exchange) {
          auto& msg = pending_messages_.back();
          if (auto r = sendMessageDirect(std::move(msg)); !r.ok()) {
            onDecodingFailure(r.status());
            return;
          }
          pending_messages_.pop_back();
        }
      }
    }
  }

  virtual void onDecodingFailure(absl::Status err) {
    if (err.ok()) {
      ENVOY_LOG(info, "ssh [{}]: stream {} closing", codec_traits<Codec>::name, streamId(), err.message());
    } else {
      ENVOY_LOG(error, "ssh [{}]: stream {} closing with error: {}", codec_traits<Codec>::name, streamId(), err.message());
    }
    callbacks_->onDecodingFailure(err.message());
  }

  void runInNextIteration(std::function<void()> fn) {
    auto id = api_.randomGenerator().uuid();
    auto* dispatcher = &callbacks_
                          ->connection()
                          ->dispatcher();
    auto cb = dispatcher->createSchedulableCallback(
      [=, this] {
        std::unique_ptr<scheduled_callback> ptr;
        std::swap(scheduled_callbacks_[id], ptr);
        scheduled_callbacks_.erase(id);
        dispatcher->deferredDelete(std::move(ptr));
        fn();
      });
    cb->scheduleCallbackNextIteration();
    scheduled_callbacks_[id] = std::make_unique<scheduled_callback>(std::move(cb));
  }

  const CipherState& getCipherStateForTest() const {
    return cipher_state_;
  }

protected:
  Callbacks* callbacks_;

  CipherState cipher_state_;
  std::unique_ptr<VersionExchanger> version_exchanger_;
  std::unique_ptr<Kex> kex_;
  std::shared_ptr<KexResult> kex_result_;
  std::optional<wire::ExtInfoMsg> outgoing_ext_info_;
  std::optional<wire::ExtInfoMsg> peer_ext_info_;

  KexAlgorithmFactoryRegistry algorithm_factories_;
  DirectionalPacketCipherFactoryRegistry cipher_factories_;

  Api::Api& api_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;

  std::string server_version_{"SSH-2.0-Envoy"};

  uint64_t resetReadSequenceNumber() override {
    return std::exchange(cipher_state_.seq_read, 0);
  }

  uint64_t resetWriteSequenceNumber() override {
    return std::exchange(cipher_state_.seq_write, 0);
  }

private:
  bool version_exchange_done_{};

  absl::StatusOr<size_t> sendMessageDirect(wire::Message&& msg) final {
    Envoy::Buffer::OwnedImpl dec;
    auto stat = wire::encodePacket(dec,
                                   msg,
                                   cipher_state_.cipher->blockSize(openssh::CipherMode::Write),
                                   cipher_state_.cipher->aadSize(openssh::CipherMode::Write));
    if (!stat.ok()) {
      return statusf("error encoding packet: {}", stat.status());
    }
    Envoy::Buffer::OwnedImpl enc;
    auto bytes_written = cipher_state_.cipher->encryptPacket(cipher_state_.seq_write++, enc, dec);
    if (!bytes_written.ok()) {
      return statusf("error encrypting packet: {}", bytes_written.status());
    }
    size_t n = enc.length();
    writeToConnection(enc);

    cipher_state_.write_bytes_remaining = sub_sat(cipher_state_.write_bytes_remaining,
                                                  static_cast<uint64_t>(*bytes_written));
    if (!cipher_state_.pending_key_exchange &&
        (cipher_state_.write_bytes_remaining == 0 || cipher_state_.seq_write > seqnum_rekey_limit)) {
      ENVOY_LOG(debug, "ssh [{}]: write rekey threshold was reached, initiating key re-exchange (bytes remaining: {}; packets sent: {})",
                codec_traits<Codec>::name, cipher_state_.write_bytes_remaining, cipher_state_.seq_write);
      auto r = kex_->initiateKex();
      if (!r.ok()) {
        return r;
      }
    }

    return n;
  }

  struct scheduled_callback : public Envoy::Event::DeferredDeletable {
    explicit scheduled_callback(Envoy::Event::SchedulableCallbackPtr cb)
        : cb(std::move(cb)) {}
    Envoy::Event::SchedulableCallbackPtr cb;
  };
  std::unordered_map<std::string, std::unique_ptr<scheduled_callback>> scheduled_callbacks_;
  std::deque<wire::Message> pending_messages_;

  void enqueueMessage(wire::Message&& msg) {
    pending_messages_.emplace_front(std::move(msg));
  }
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec