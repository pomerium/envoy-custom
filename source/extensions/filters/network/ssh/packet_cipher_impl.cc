#include "source/extensions/filters/network/ssh/packet_cipher_impl.h"

#include <cstdint>
#include <algorithm>
#include <iterator>

#include "source/extensions/filters/network/ssh/wire/common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

PacketCipher::PacketCipher(std::unique_ptr<DirectionalPacketCipher> read,
                           std::unique_ptr<DirectionalPacketCipher> write)
    : read_(std::move(read)), write_(std::move(write)) {}

absl::StatusOr<size_t> PacketCipher::encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                                   Envoy::Buffer::Instance& in) {
  return write_->encryptPacket(seqnum, out, in);
}

absl::StatusOr<size_t> PacketCipher::decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                                   Envoy::Buffer::Instance& in) {
  return read_->decryptPacket(seqnum, out, in);
}

size_t PacketCipher::rekeyAfterBytes(openssh::CipherMode mode) {
  // RFC4344 § 3.2 states:
  //  Let L be the block length (in bits) of an SSH encryption method's
  //  block cipher (e.g., 128 for AES).  If L is at least 128, then, after
  //  rekeying, an SSH implementation SHOULD NOT encrypt more than 2**(L/4)
  //  blocks before rekeying again.

  auto l = blockSize(mode) * 8;
  if (l >= 128) {
    return 1 << (l / 4);
  }

  // cont.:
  //  If L is less than 128, [...] rekey at least once for every gigabyte
  //  of transmitted data.
  return 1 << 30;
}

AEADPacketCipher::AEADPacketCipher(const char* cipher_name, bytes iv, bytes key,
                                   openssh::CipherMode mode)
    : ctx_(openssh::SSHCipher(cipher_name, iv, key, mode)) {}

absl::StatusOr<size_t> AEADPacketCipher::encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                                       Envoy::Buffer::Instance& in) {

  return ctx_.encryptPacket(seqnum, out, in);
}

absl::StatusOr<size_t> AEADPacketCipher::decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                                       Envoy::Buffer::Instance& in) {
  auto in_length = in.length();
  if (in_length < ctx_.blockSize()) {
    return 0; // incomplete packet
  }

  uint32_t packlen = 0;
  if (auto l = ctx_.packetLength(seqnum, in); !l.ok()) {
    return l.status();
  } else {
    packlen = *l;
  }

  auto r = ctx_.decryptPacket(seqnum, out, in, packlen);
  if (!r.ok()) {
    return r.status();
  }

  return *r;
}

size_t AEADPacketCipher::blockSize() {
  return ctx_.blockSize();
};

size_t AEADPacketCipher::aadLen() {
  return ctx_.aadLen();
};

namespace {
void generateKeyMaterial(bytes& out, char tag, KexResult* kex_result) {
  // translated from go ssh/transport.go
  bytes digestsSoFar;

  using namespace std::placeholders;
  while (out.size() < out.capacity()) {
    size_t digest_size = 0;
    bssl::ScopedEVP_MD_CTX ctx;
    switch (kex_result->hash) {
    case SHA256:
      EVP_DigestInit(ctx.get(), EVP_sha256());
      digest_size = 32;
      break;
    case SHA512:
      EVP_DigestInit(ctx.get(), EVP_sha512());
      digest_size = 64;
      break;
    default:
      throw EnvoyException("unsupported hash algorithm");
    }
    bytes encoded_k;
    kex_result->encodeSharedSecret(encoded_k);
    EVP_DigestUpdate(ctx.get(), encoded_k.data(), encoded_k.size());
    EVP_DigestUpdate(ctx.get(), kex_result->exchange_hash.data(), kex_result->exchange_hash.size());
    if (digestsSoFar.size() == 0) {
      EVP_DigestUpdate(ctx.get(), &tag, 1);
      EVP_DigestUpdate(ctx.get(), kex_result->session_id.data(), kex_result->session_id.size());
    } else {
      EVP_DigestUpdate(ctx.get(), digestsSoFar.data(), digestsSoFar.size());
    }
    bytes digest(digest_size, 0);
    EVP_DigestFinal(ctx.get(), digest.data(), nullptr);
    auto toCopy = std::min(out.capacity() - out.size(), digest.size());
    if (toCopy > 0) {
      std::copy_n(digest.begin(), toCopy, std::back_inserter(out));
      std::copy(digest.begin(), digest.end(), std::back_inserter(digestsSoFar));
    }
  }
}
} // namespace

std::unique_ptr<PacketCipher> PacketCipherFactory::makePacketCipher(direction_t d_read, direction_t d_write,
                                                                    KexResult* kex_result) {
  ASSERT(!kex_result->session_id.empty());
  if (ciphers.contains(kex_result->algorithms.r.cipher) &&
      ciphers.contains(kex_result->algorithms.w.cipher)) {

    const auto& readMode = ciphers.at(kex_result->algorithms.r.cipher);
    const auto& writeMode = ciphers.at(kex_result->algorithms.w.cipher);

    bytes readIv;
    readIv.reserve(readMode.ivSize);
    generateKeyMaterial(readIv, d_read.iv_tag, kex_result);
    bytes readKey;
    readKey.reserve(readMode.keySize);
    generateKeyMaterial(readKey, d_read.key_tag, kex_result);

    // todo: non-aead ciphers?

    bytes writeIv;
    writeIv.reserve(writeMode.ivSize);
    generateKeyMaterial(writeIv, d_write.iv_tag, kex_result);
    bytes writeKey;
    writeKey.reserve(writeMode.keySize);
    generateKeyMaterial(writeKey, d_write.key_tag, kex_result);

    return std::make_unique<PacketCipher>(readMode.create(readIv, readKey, openssh::CipherMode::Read),
                                          writeMode.create(writeIv, writeKey, openssh::CipherMode::Write));
  }
  ENVOY_LOG(error, "unsupported algorithm; read={}, write={}",
            kex_result->algorithms.r.cipher, kex_result->algorithms.w.cipher);
  throw EnvoyException("unsupported algorithm"); // shouldn't get here ideally
}

size_t PacketCipher::blockSize(openssh::CipherMode mode) {
  switch (mode) {
  case openssh::CipherMode::Read:
    return read_->blockSize();
  case openssh::CipherMode::Write:
    return write_->blockSize();
  }
  throw EnvoyException("unknown mode");
}

size_t PacketCipher::aadSize(openssh::CipherMode mode) {
  switch (mode) {
  case openssh::CipherMode::Read:
    return read_->aadLen();
  case openssh::CipherMode::Write:
    return write_->aadLen();
  }
  throw EnvoyException("unknown mode");
}

std::unique_ptr<PacketCipher> PacketCipherFactory::makeUnencryptedPacketCipher() {
  return std::make_unique<PacketCipher>(std::make_unique<NoCipher>(), std::make_unique<NoCipher>());
}

absl::StatusOr<size_t> NoCipher::decryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                                               Envoy::Buffer::Instance& in) {
  uint32_t packlen = in.peekBEInt<uint32_t>();
  if (packlen < wire::MinPacketSize || packlen > wire::MaxPacketSize) {
    return absl::AbortedError("invalid packet size");
  }
  uint32_t need = packlen + 4;
  if (in.length() < need) {
    return 0; // incomplete packet
  }
  out.move(in, need);
  return need;
}

absl::StatusOr<size_t> NoCipher::encryptPacket(uint32_t /*seqnum*/, Envoy::Buffer::Instance& out,
                                               Envoy::Buffer::Instance& in) {
  size_t in_len = in.length();
  out.move(in, in_len);
  return in_len;
}

size_t NoCipher::blockSize() {
  // Minimum block size is 8 according to RFC4253 § 6
  return 8;
}

size_t NoCipher::aadLen() {
  return 0;
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec