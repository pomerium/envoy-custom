#pragma once

#include <cstddef>
#include <memory>
#include <string>

#include "source/extensions/filters/network/ssh/kex_alg.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/version_exchange.h"
#include "source/extensions/filters/network/ssh/message_handler.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

struct KexState {
  bool kex_strict{};
  wire::KexInitMsg our_kex{};
  wire::KexInitMsg peer_kex{};
  Algorithms negotiated_algorithms{};
  HandshakeMagics magics{};

  std::unique_ptr<KexAlgorithm> alg_impl;
  KexResultSharedPtr kex_result;

  bool kex_init_sent{};
  bool kex_init_received{};
  bool client_supports_ext_info{};
  bool server_supports_ext_info{};
  bool ext_info_sent{};
  bool ext_info_received{};
  bool ext_info_recv_permitted{};

  bool kex_rsa_sha2_256_supported{};
  bool kex_rsa_sha2_512_supported{};
};

class KexCallbacks : public VersionExchangeCallbacks {
public:
  virtual ~KexCallbacks() = default;
  virtual void onKexStarted(bool initial_kex) PURE;
  virtual void onKexCompleted(std::shared_ptr<KexResult> kex_result, bool initial_kex) PURE;
  virtual void onKexInitMsgSent() PURE;
};

enum class KexMode {
  Server = 1,
  Client = 2,
};

inline const DirectionAlgorithms& readDirectionAlgsForMode(Algorithms& algorithms, KexMode mode) {
  switch (mode) {
  case KexMode::Server:
    return algorithms.client_to_server;
  case KexMode::Client:
    return algorithms.server_to_client;
  default:
    throw Envoy::EnvoyException("invalid KexMode");
  }
}

inline const DirectionAlgorithms& writeDirectionAlgsForMode(Algorithms& algorithms, KexMode mode) {
  switch (mode) {
  case KexMode::Server:
    return algorithms.server_to_client;
  case KexMode::Client:
    return algorithms.client_to_server;
  default:
    throw Envoy::EnvoyException("invalid KexMode");
  }
}

std::unique_ptr<PacketCipher>
makePacketCipherFromKexResult(DirectionalPacketCipherFactoryRegistry& cipher_factories,
                              DirectionTags d_read,
                              DirectionTags d_write,
                              KexMode mode,
                              KexResult* kex_result);

template <typename T>
struct codec_traits;

template <typename Codec>
auto makePacketCipherFromKexResult(DirectionalPacketCipherFactoryRegistry& cipher_factories,
                                   KexResult* kex_result) {
  return makePacketCipherFromKexResult(cipher_factories,
                                       codec_traits<Codec>::direction_read,
                                       codec_traits<Codec>::direction_write,
                                       codec_traits<Codec>::kex_mode,
                                       kex_result);
}

class Kex final : public VersionExchangeCallbacks,
                  public SshMessageHandler,
                  public Logger::Loggable<Logger::Id::filter> {
public:
  Kex(TransportCallbacks& transport_callbacks,
      KexCallbacks& kex_callbacks,
      KexAlgorithmFactoryRegistry& algorithm_factories,
      DirectionalPacketCipherFactoryRegistry& cipher_factories,
      KexMode mode);

  absl::Status initiateKex();
  const openssh::SSHKey* pickHostKey(std::string_view alg) const;
  const openssh::SSHKey* getHostKey(sshkey_types pkalg) const;

  // SshMessageHandler
  void registerMessageHandlers(MessageDispatcher<wire::Message>& dispatcher) override;
  absl::Status handleMessage(wire::Message&& msg) noexcept override;

  // VersionExchangeCallbacks
  void onVersionExchangeCompleted(const bytes& server_version,
                                  const bytes& client_version,
                                  const bytes& banner) override;

  void setHostKeys(std::vector<openssh::SSHKeyPtr> host_keys);

  KexState& getPendingStateForTest() const { return *pending_state_; }

private:
  struct IncorrectGuessMsgHandler final : public SshMessageMiddleware {
    explicit IncorrectGuessMsgHandler(Kex& self)
        : self(self) {}
    absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override;
    Kex& self;
  };
  struct KexAlgMsgHandler final : public SshMessageMiddleware {
    explicit KexAlgMsgHandler(Kex& self)
        : self(self) {}
    absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override;
    Kex& self;
  };
  struct NewKeysMsgHandler final : public SshMessageMiddleware {
    explicit NewKeysMsgHandler(Kex& self)
        : self(self) {}
    absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override;
    Kex& self;
  };
  struct ExtInfoMsgHandler final : public SshMessageMiddleware {
    explicit ExtInfoMsgHandler(Kex& self)
        : self(self) {}
    absl::StatusOr<MiddlewareResult> interceptMessage(wire::Message& msg) override;
    Kex& self;
  };

  KexAlgMsgHandler msg_handler_kex_alg_{*this};
  NewKeysMsgHandler msg_handler_new_keys_{*this};
  ExtInfoMsgHandler msg_handler_ext_info_{*this};
  IncorrectGuessMsgHandler msg_handler_incorrect_guess_{*this};

  absl::StatusOr<Algorithms> findAgreedAlgorithms(bool initial_kex) const noexcept;
  absl::StatusOr<std::string> findCommon(const std::string_view what,
                                         const string_list& client,
                                         const string_list& server) const;

  std::unique_ptr<KexAlgorithm> createKexAlgorithm() const;

  absl::Status sendKexInitMsg(bool initial_kex) noexcept;
  absl::Status sendNewKeysMsg();
  void onNewKeysMsgReceived();
  inline bool isInitialKex() const { return active_state_ == nullptr; }

  TransportCallbacks& transport_;
  KexCallbacks& kex_callbacks_;
  KexAlgorithmFactoryRegistry& algorithm_factories_;
  DirectionalPacketCipherFactoryRegistry& cipher_factories_;

  bytes server_version_;
  bytes client_version_;
  bytes version_exchange_banner_;
  std::unique_ptr<KexState> pending_state_;
  std::unique_ptr<KexState> active_state_;
  bool is_server_;
  std::vector<openssh::SSHKeyPtr> host_keys_;
  Envoy::OptRef<MessageDispatcher<wire::Message>> msg_dispatcher_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec