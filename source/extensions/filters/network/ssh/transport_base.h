#pragma once

#include <concepts>

#include "source/common/math.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/generic_proxy/interface/codec.h"

#include "source/extensions/filters/network/ssh/kex.h"
#include "source/extensions/filters/network/ssh/kex_alg_curve25519.h"
#include "source/extensions/filters/network/ssh/kex_alg_mlkem.h"
#include "source/extensions/filters/network/ssh/packet_cipher_aead.h"
#include "source/extensions/filters/network/ssh/packet_cipher_etm.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/transport.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

template <typename T>
  requires std::derived_from<T, ServerCodec>
struct codec_traits<T> {
  using callbacks_type = ServerCodecCallbacks;
  static constexpr DirectionTags direction_read = clientKeys;
  static constexpr DirectionTags direction_write = serverKeys;
  static constexpr auto kex_mode = KexMode::Server;
  static constexpr auto version_exchange_mode = VersionExchangeMode::Server;
  static constexpr std::string_view name = "server";
};

template <typename T>
  requires std::derived_from<T, ClientCodec>
struct codec_traits<T> {
  using callbacks_type = ClientCodecCallbacks;
  static constexpr DirectionTags direction_read = serverKeys;
  static constexpr DirectionTags direction_write = clientKeys;
  static constexpr auto kex_mode = KexMode::Client;
  static constexpr std::string_view name = "client";
  static constexpr auto version_exchange_mode = VersionExchangeMode::Client;
};

// RFC4344 § 3.1 states:
//  SSH implementations SHOULD also attempt to rekey before receiving
//  more than 2**32 packets since the last rekey operation.  The
//  preferred way to do this is to rekey after receiving more than 2**31
//  packets since the last rekey operation.
//
// Note that because we require strict key exchange, the sequence number is used to determine how
// many packets have been sent/received.
static constexpr uint32_t SeqnumRekeyLimit = (static_cast<uint32_t>(1) << 31);

template <typename Codec>
class TransportBase : public Codec,
                      public KexCallbacks,
                      public SshMessageDispatcher,
                      public SshMessageHandler,
                      public virtual TransportCallbacks,
                      public Logger::Loggable<Logger::Id::filter> {
public:
  TransportBase(Server::Configuration::ServerFactoryContext& context,
                std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config,
                const SecretsProvider& secrets_provider)
      : api_(context.api()),
        config_(config),
        secrets_provider_(secrets_provider),
        scope_(context.scope().createScope("ssh")) {
    auto maskedKexAlgNames = config_->algorithm_options().disable_kex_algorithms();
    algorithm_factories_.setMaskedNames({maskedKexAlgNames.begin(), maskedKexAlgNames.end()});
    auto maskedCipherAlgNames = config_->algorithm_options().disable_packet_cipher_algorithms();
    cipher_factories_.setMaskedNames({maskedCipherAlgNames.begin(), maskedCipherAlgNames.end()});

    algorithm_factories_.registerType<Curve25519Sha256KexAlgorithmFactory>();
    algorithm_factories_.registerType<Mlkem768x25519KexAlgorithmFactory>();
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
    kex_->setHostKeys(secrets_provider_.hostKeys());
    version_exchanger_ = std::make_unique<VersionExchanger>(*this, *kex_, codec_traits<Codec>::version_exchange_mode);

    cipher_ = std::make_unique<PacketCipher>(std::make_unique<NoCipher>(), std::make_unique<NoCipher>());
    seq_read_ = 0;
    seq_write_ = 0;
    read_bytes_remaining_ = cipher_->rekeyAfterBytes(openssh::CipherMode::Read);
    write_bytes_remaining_ = cipher_->rekeyAfterBytes(openssh::CipherMode::Write);
  }

  // Notes on buffer watermark configuration:
  //
  // It is very important that the connection buffer high watermark is set to a value at least twice
  // as large as the maximum allowed ssh packet size, to avoid a situation where an incomplete
  // packet with a size greater than the low watermark threshold would prevent a buffer that has had
  // its high watermark triggered from ever reaching the low watermark.
  //
  // Example: consider a read buffer with a buffer limit of 50. When a read event is triggered and
  // decode() is called, there could be multiple packets (denoted below as `[--#--]`) available in
  // the buffer to read. Note that the high watermark only triggers when the buffer size exceeds it,
  // so in the diagram below the position marked with H is the limit, and any additional bytes will
  // trigger the HWM. The low watermark is always H/2.
  //
  //            H------------------------L------------------------
  //  Write ->                                     [-3-][--2--][1] -> Read
  //            H------------------------L------------------------
  //            ^ High Watermark         ^ Low Watermark
  //
  // In the above example we will read packets 1 2 and 3, then yield control back to envoy as the
  // buffer will be empty.
  //
  // It is also possible that the trailing packet in the buffer is incomplete at the time decode()
  // is called, and we need to yield with bytes still remaining in the buffer:
  //
  //                             before decode()
  //            H------------------------L------------------------
  //  Write ->                               --3---][--2--][--1--] -> Read
  //            H------------------------L------------------------
  //                             after decode()
  //            H------------------------L------------------------
  //  Write ->                                             --3---] -> Read
  //            H------------------------L------------------------
  //
  // If the buffer has a size of 50, envoy might write 50 bytes at a time into the buffer then
  // trigger a read event, and repeat. This is to avoid repeatedly triggering the watermarks.
  //
  //                             before decode()
  //            H------------------------L------------------------
  //  Write ->  -9-][---8---][-7-][--6--][5][--4--][-3-][--2--][1] -> Read
  //            H------------------------L------------------------
  //                             after decode()
  //            H------------------------L------------------------
  //  Write ->                                                -9-] -> Read
  //            H------------------------L------------------------
  //
  // Next, envoy could write 46 bytes into the buffer to avoid triggering the HWM. It could also
  // write more (the watermarks are soft limits). If it does, then the HWM will trigger and writes
  // to the buffer will be temporarily disabled:
  //
  //            H------------------------L------------------------
  //  W ->  [---13---][------12------][----11----][----10----][-9- -> Read
  //            H------------------------L------------------------
  //        ^^^^ triggers HWM
  //
  // No additional data will be written to the buffer until the buffer is drained to the low
  // watermark threshold:
  //
  //              Read packet 9 (writes still blocked)
  //            H------------------------L------------------------
  //            [---13---][------12------][----11----][----10----] -> Read
  //            H------------------------L------------------------
  //              Read packet 10 (writes still blocked)
  //            H------------------------L------------------------
  //                        [---13---][------12------][----11----] -> Read
  //            H------------------------L------------------------
  //              Read packet 11 (writes still blocked)
  //            H------------------------L------------------------
  //                                    [---13---][------12------] -> Read
  //            H------------------------L------------------------
  //              Read packet 12 (low watermark triggered, writes unblocked)
  //            H------------------------L------------------------
  //  Write ->                                          [---13---] -> Read
  //            H------------------------L------------------------
  //
  //
  // A problem arises if the low watermark threshold is smaller than the max allowed packet size:
  //
  //              Large incomplete packet is written (high watermark triggered)
  //            H------------------------L------------------------
  //  W ->  ------------16---------------][----15----][----14----] -> Read
  //            H------------------------L------------------------
  //              Read packet 14 (writes still blocked)
  //            H------------------------L------------------------
  //                    ------------16---------------][----15----] -> Read
  //            H------------------------L------------------------
  //              Read packet 15 (writes still blocked)
  //            H------------------------L------------------------
  //                                ------------16---------------] -> Read
  //            H------------------------L------------------------
  //
  // In this situation, packet 16 won't be read from the buffer because it is incomplete, but it is
  // also large enough to prevent the low watermark from being activated. No new data will be
  // written, so the connection is deadlocked.
  //
  // To prevent this situation, ensure the high watermark is at least 524288 bytes, which is twice
  // the size of the largest allowed ssh packet (262144 bytes). Then, the low watermark (always
  // HWM/2, not configurable) will be large enough to hold any packet.
  //
  void decode(Envoy::Buffer::Instance& buffer, bool /*end_stream*/) override {
    while (buffer.length() > 0) {
      if (!version_exchange_done_) {
        // Sanity check that the buffer high watermark can accomodate the entire version exchange.
        // Note that MaxVersionExchangeBytes is much smaller than the actual required minimum
        ASSERT(buffer.highWatermark() == 0 || buffer.highWatermark() >= MaxVersionExchangeBytes,
               "configuration error: buffer high watermark is too small for version exchange");
        // This is the only place where readVersion should be called; if the version is read
        // completely, it must return an OK status with non-zero value, then continue on to set
        // the version_exchange_done_ flag to true. So, we should not be able to get here unless
        // versionRead() is false.
        ASSERT(!version_exchanger_->versionRead());
        auto n = version_exchanger_->readVersion(buffer);
        if (!n.ok()) {
          terminate(n.status());
          return;
        }
        if (*n == 0) {
          ENVOY_LOG(trace, "received incomplete packet; waiting for more data");
          return;
        }

        if (!version_exchanger_->versionWritten()) {
          version_exchanger_->writeVersion(server_version_);
        }
        version_exchange_done_ = true;
        continue;
      }

      Envoy::Buffer::OwnedImpl dec;
      auto bytes_read = cipher_->decryptPacket(seq_read_, dec, buffer);
      if (!bytes_read.ok()) {
        terminate(statusf("failed to decrypt packet: {}", bytes_read.status()));
        return;
      }
      if (*bytes_read == 0) {
        ENVOY_BUG(!buffer.highWatermarkTriggered(),
                  fmt::format("connection deadlocked: buffer high watermark is too small "
                              "(current value {} is less than the required minimum {})",
                              buffer.highWatermark(), wire::MaxPacketSize * 2));
        // Note: sequence number not increased
        ENVOY_LOG(trace, "received incomplete packet; waiting for more data");
        return;
      }
      // Only increase the sequence number after reading a full packet
      seq_read_++;

      wire::Message msg;
      auto packet_len = wire::decodePacket(dec, msg);
      if (!packet_len.ok()) {
        terminate(statusf("failed to decode packet: {}", packet_len.status()));
        return;
      }
      ENVOY_LOG(trace, "ssh [{}]: stream {}: received message: size: {}, type: {}",
                codec_traits<Codec>::name, streamId(), *packet_len, msg.msg_type());
      if (auto err = onMessageDecoded(std::move(msg)); !err.ok()) {
        terminate(err);
        return;
      }

      // Check if we need to initiate a key re-exchange
      //
      // Note: during key re-exchange, if the message we just decoded was the peer's NewKeys, the
      // onMessageDecoded callback above will have reset seq_read_, read_bytes_remaining_,
      // and set pending_key_exchange_ to false.
      read_bytes_remaining_ = sub_sat(read_bytes_remaining_, static_cast<uint64_t>(*bytes_read));
      if (!pending_key_exchange_ &&
          (read_bytes_remaining_ == 0 || seq_read_ > SeqnumRekeyLimit)) {
        ENVOY_LOG(debug, "ssh [{}]: read rekey threshold was reached, initiating key re-exchange (bytes remaining: {}; packets sent: {})",
                  codec_traits<Codec>::name,
                  read_bytes_remaining_, seq_read_);
        if (auto stat = kex_->initiateKex(); !stat.ok()) {
          terminate(statusf("failed to initiate rekey: {}", stat));
          return;
        }
      }
    }
  }

  void writeToConnection(Envoy::Buffer::Instance& buf) const final {
    return callbacks_->writeToConnection(buf);
  }

  absl::StatusOr<size_t> sendMessageToConnection(wire::Message&& msg) override {
    if (!pending_key_exchange_) [[likely]] {
      return sendMessageDirect(std::move(msg));
    }
    if (msg.msg_type() == wire::SshMessageType::Disconnect) {
      // disconnect messages are always sent immediately
      return sendMessageDirect(std::move(msg));
    }
    ENVOY_LOG(debug, "queueing message due to pending key exchange: {}", msg.msg_type());
    enqueueMessage(std::move(msg));
    return 0uz;
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

  virtual absl::Status onMessageDecoded(wire::Message&& msg) {
    if (!msg.has_value()) [[unlikely]] {
      // https://datatracker.ietf.org/doc/html/rfc4253#section-11.4
      auto seqnum = sub_sat(seq_read_, static_cast<uint32_t>(1)); // sequence number we just read
      return sendMessageToConnection(wire::UnimplementedMsg{.sequence_number = seqnum}).status();
    }
    return dispatch(std::move(msg));
  }

  void onVersionExchangeCompleted(const bytes& server_version, const bytes& client_version, const bytes&) override {
    std::string serverVersionString(reinterpret_cast<const char*>(server_version.data()),
                                    server_version.size());
    std::string clientVersionString(reinterpret_cast<const char*>(client_version.data()),
                                    client_version.size());
    ENVOY_LOG(debug, "ssh [{}]: stream {}: version exchange complete (server: {}; client: {})",
              codec_traits<Codec>::name, streamId(), serverVersionString, clientVersionString);
    if (auto stat = kex_->initiateKex(); !stat.ok()) {
      terminate(stat);
    }
  }

  // If overriding (tests only), be sure to call this function in the implementation
  void onKexInitMsgSent() override {
    pending_key_exchange_ = true;
  }

  void onKexStarted(bool initial_kex) override {
    if (initial_kex) {
      ENVOY_LOG(debug, "ssh [{}]: starting initial key exchange", codec_traits<Codec>::name);
    } else {
      ENVOY_LOG(debug, "ssh [{}]: starting key re-exchange", codec_traits<Codec>::name);
    }
  }

  void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) override {
    ASSERT(pending_key_exchange_);
    kex_result_ = kex_result;

    cipher_ = makePacketCipherFromKexResult<Codec>(cipher_factories_, kex_result.get());
    if (config_->has_rekey_threshold()) {
      read_bytes_remaining_ = std::max<uint64_t>(256, config_->rekey_threshold().value());
      write_bytes_remaining_ = std::max<uint64_t>(256, config_->rekey_threshold().value());
    } else {
      read_bytes_remaining_ = cipher_->rekeyAfterBytes(openssh::CipherMode::Read);
      write_bytes_remaining_ = cipher_->rekeyAfterBytes(openssh::CipherMode::Write);
    }
    ENVOY_LOG(debug, "ssh [{}]: new read bytes remaining: {}", codec_traits<Codec>::name, read_bytes_remaining_);
    ENVOY_LOG(debug, "ssh [{}]: new write bytes remaining: {}", codec_traits<Codec>::name, write_bytes_remaining_);

    pending_key_exchange_ = false;

    if (initial_kex) {
      ENVOY_LOG(debug, "ssh [{}]: initial key exchange completed", codec_traits<Codec>::name);
      this->registerMessageHandlers(*static_cast<SshMessageDispatcher*>(this));
      ENVOY_BUG(pending_messages_.empty(), "extra messages sent before initial key exchange complete");
      pending_messages_.clear();
    } else {
      ENVOY_LOG(debug, "ssh [{}]: key re-exchange completed", codec_traits<Codec>::name);

      if (!pending_messages_.empty()) {
        ENVOY_LOG(debug, "ssh [{}]: sending {} messages queued during key re-exchange",
                  codec_traits<Codec>::name, pending_messages_.size());
        while (!pending_messages_.empty() && !pending_key_exchange_) {
          auto& msg = pending_messages_.back();
          if (auto r = sendMessageDirect(std::move(msg)); !r.ok()) {
            terminate(r.status());
            return;
          }
          pending_messages_.pop_back();
        }
      }
    }
  }

  void terminate(absl::Status err) override {
    ENVOY_LOG(error, "ssh [{}]: stream {} closing with error: {}", codec_traits<Codec>::name, streamId(), err.message());
    callbacks_->onDecodingFailure(err.message());
  }

  void connectionReadDisable(bool disable) override {
    callbacks_->connection()->readDisable(disable);
  }

  const bytes& sessionId() const final { return kex_result_->session_id; }
  const SecretsProvider& secretsProvider() const final { return secrets_provider_; }
  Stats::Scope& statsScope() const override { return *scope_; }

protected:
  bool version_exchange_done_{};
  bool pending_key_exchange_{};
  uint32_t seq_read_{};
  uint32_t seq_write_{};
  std::unique_ptr<PacketCipher> cipher_;
  uint64_t read_bytes_remaining_{};
  uint64_t write_bytes_remaining_{};

  Callbacks* callbacks_;
  std::unique_ptr<VersionExchanger> version_exchanger_;
  std::unique_ptr<Kex> kex_;
  std::shared_ptr<KexResult> kex_result_;
  std::optional<wire::ExtInfoMsg> outgoing_ext_info_;
  std::optional<wire::ExtInfoMsg> peer_ext_info_;

  KexAlgorithmFactoryRegistry algorithm_factories_;
  DirectionalPacketCipherFactoryRegistry cipher_factories_;

  Api::Api& api_;
  std::shared_ptr<pomerium::extensions::ssh::CodecConfig> config_;
  const SecretsProvider& secrets_provider_;

  std::string server_version_{"SSH-2.0-Envoy"};

  uint64_t resetReadSequenceNumber() override {
    return std::exchange(seq_read_, 0);
  }

  uint64_t resetWriteSequenceNumber() override {
    return std::exchange(seq_write_, 0);
  }

  absl::StatusOr<size_t> sendMessageDirect(wire::Message&& msg) override {
    Envoy::Buffer::OwnedImpl dec;
    auto packet_len = wire::encodePacket(dec,
                                         msg,
                                         cipher_->blockSize(openssh::CipherMode::Write),
                                         cipher_->aadSize(openssh::CipherMode::Write));
    if (!packet_len.ok()) {
      return statusf("error encoding packet: {}", packet_len.status());
    }
    Envoy::Buffer::OwnedImpl enc;

    auto stat = cipher_->encryptPacket(seq_write_++, enc, dec);
    ASSERT(stat.ok()); // this should not normally fail

    size_t n = enc.length();
    writeToConnection(enc);

    write_bytes_remaining_ = sub_sat(write_bytes_remaining_,
                                     static_cast<uint64_t>(*packet_len));
    if (!pending_key_exchange_ &&
        (write_bytes_remaining_ == 0 || seq_write_ > SeqnumRekeyLimit)) {
      ENVOY_LOG(debug, "ssh [{}]: write rekey threshold was reached, initiating key re-exchange (bytes remaining: {}; packets sent: {})",
                codec_traits<Codec>::name, write_bytes_remaining_, seq_write_);
      if (auto stat = kex_->initiateKex(); !stat.ok()) {
        return statusf("failed to initiate rekey: {}", stat);
      }
    }

    return n;
  }

private:
  std::deque<wire::Message> pending_messages_;
  Stats::ScopeSharedPtr scope_;

  void enqueueMessage(wire::Message&& msg) {
    pending_messages_.emplace_front(std::move(msg));
  }
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec