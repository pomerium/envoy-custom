#pragma once

#include "source/extensions/filters/network/ssh/util.h"
#include "source/extensions/filters/network/ssh/messages.h"
#include "source/extensions/filters/network/ssh/kex.h"
#include <memory>
#include <openbsd-compat/sha2.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

class PacketCipher {
public:
  virtual ~PacketCipher() = default;
  virtual error_or<std::string> encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& in) PURE;
  virtual error decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                              std::string ciphertext) PURE;
};

class Chacha20Poly1305Cipher : public PacketCipher {
public:
  Chacha20Poly1305Cipher(std::basic_string_view<uint8_t> key) {
    memcpy(content_key_, key.substr(0, 32).data(), sizeof(content_key_));
    memcpy(length_key_, key.substr(32).data(), sizeof(length_key_));
  }

  error_or<std::string> encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& in) override {}
  error decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                      std::string ciphertext) override {}

private:
  uint8_t content_key_[32];
  uint8_t length_key_[32];
};

// code below mostly translated from go ssh/transport.go

inline void generateKeyMaterial(uint8_t* out, size_t out_len, std::basic_string_view<uint8_t> tag,
                                kex_result_t* kex_result) {
  std::basic_string<uint8_t> digestsSoFar;
  using namespace std::placeholders;
  while (out_len > 0) {
    std::function<void(const uint8_t*, size_t)> write;
    std::function<void(uint8_t*)> sum;
    size_t digest_size;
    SHA2_CTX hash_ctx;
    switch (kex_result->Hash) {
    case SHA256:
      SHA256Init(&hash_ctx);
      write = std::bind(&SHA256Update, &hash_ctx, _1, _2);
      sum = std::bind(&SHA256Final, _1, &hash_ctx);
      digest_size = 32;
    case SHA512:
      SHA512Init(&hash_ctx);
      write = std::bind(&SHA512Update, &hash_ctx, _1, _2);
      sum = std::bind(&SHA512Final, _1, &hash_ctx);
      digest_size = 64;
    default:
      throw EnvoyException("unsupported hash algorithm");
    }
    if (digestsSoFar.length() == 0) {
      write(tag.data(), tag.length());
      write(reinterpret_cast<uint8_t*>(kex_result->SessionID.data()),
            kex_result->SessionID.length());
    } else {
      write(digestsSoFar.data(), digestsSoFar.length());
    }
    std::basic_string<uint8_t> digest(digest_size, 0);
    sum(digest.data());
    memcpy(out, digest.data(), digest_size);
    out += digest_size;
    out_len -= digest_size;
    if (out_len > 0) {
      digestsSoFar += digest;
    }
  }
}

inline std::unique_ptr<PacketCipher>
NewPacketCipher(direction_t direction, direction_algorithms_t algs, kex_result_t* kex_result) {
  if (cipherModes.contains(algs.cipher)) {
    auto mode = cipherModes.at(algs.cipher);
    std::basic_string<uint8_t> key(mode.keySize, 0);
    generateKeyMaterial(key.data(), key.length(), direction.key_tag, kex_result);
    return mode.create(key);
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec