#include "source/extensions/filters/network/ssh/packet_cipher_impl.h"

#include <algorithm>
#include <iterator>

#include "source/extensions/filters/network/ssh/kex.h"

extern "C" {
#include "openssh/ssherr.h"
#include "openssh/cipher.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

PacketCipher::PacketCipher(std::unique_ptr<DirectionalPacketCipher> read,
                           std::unique_ptr<DirectionalPacketCipher> write)
    : read_(std::move(read)), write_(std::move(write)) {}

absl::Status PacketCipher::encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                         Envoy::Buffer::Instance& in) {
  return write_->encryptPacket(seqnum, out, in);
}

absl::Status PacketCipher::decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                         Envoy::Buffer::Instance& in) {
  return read_->decryptPacket(seqnum, out, in);
}

AEADPacketCipher::AEADPacketCipher(const char* cipher_name, bytes /*iv*/, bytes key,
                                   Mode mode) {
  auto cipher = cipher_by_name(cipher_name);
  block_len_ = cipher_blocksize(cipher);
  auth_len_ = cipher_authlen(cipher);
  iv_len_ = cipher_ivlen(cipher);
  aad_len_ = 4;
  sshcipher_ctx* cipher_ctx;
  cipher_init(&cipher_ctx, cipher, key.data(), static_cast<uint32_t>(key.size()), nullptr, 0, mode);
  ctx_.reset(cipher_ctx);
}

absl::Status AEADPacketCipher::encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                             Envoy::Buffer::Instance& in) {

  auto in_length = in.length();
  auto in_data = static_cast<uint8_t*>(in.linearize(static_cast<uint32_t>(in_length)));
  uint32_t packlen = static_cast<uint32_t>(in_length);

  bytes out_data;
  out_data.resize(packlen + auth_len_);

  auto r = cipher_crypt(ctx_.get(), seqnum, out_data.data(), in_data,
                        static_cast<uint32_t>(packlen - aad_len_),
                        static_cast<uint32_t>(aad_len_),
                        static_cast<uint32_t>(auth_len_));
  if (r != 0) {
    return absl::AbortedError(fmt::format("cipher_crypt failed: {}", ssh_err(r)));
  }

  in.drain(in_length);
  out.add(out_data.data(), out_data.size());
  return absl::OkStatus();
}

absl::Status AEADPacketCipher::decryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                             Envoy::Buffer::Instance& in) {
  if (in.length() < block_len_) {
    return absl::OkStatus(); // incomplete packet
  }

  auto in_length = in.length();
  auto in_data = static_cast<uint8_t*>(in.linearize(static_cast<uint32_t>(in_length)));
  uint32_t packlen = 0;
  if (cipher_get_length(ctx_.get(), &packlen, seqnum, in_data, static_cast<uint32_t>(in_length)) != 0) {
    return absl::AbortedError("packet too small");
  }
  if (packlen < wire::MinPacketSize || packlen > wire::MaxPacketSize) {
#ifdef SSH_DEBUG_SEQNUM
    for (auto test : std::vector<uint32_t>{seqnum - 1, seqnum + 1, seqnum - 2, seqnum + 2, 0}) {
      if (cipher_get_length(ctx_.get(), &packlen, test, in_data, in_length) == 0 &&
          packlen < wire::MaxPacketSize) {
        ENVOY_LOG(warn, "sequence number drift: packet decrypts with seqnr={}, but ours is {}",
                  test, seqnum);
      }
    }
#endif
    return absl::AbortedError(fmt::format("bad packet length: {} (seqnr {})", packlen, seqnum));
  }
  if (packlen % block_len_ != 0) {
    return absl::AbortedError(fmt::format("padding error: need {} block {} mod {}", packlen,
                                          block_len_, packlen % block_len_));
  }
  if (in_length < aad_len_ + packlen + auth_len_) {
    return absl::OkStatus(); // incomplete packet
  }

  bytes out_data;
  out_data.resize(packlen + aad_len_);

  auto r = cipher_crypt(ctx_.get(), seqnum, out_data.data(), in_data, packlen,
                        static_cast<uint32_t>(aad_len_), static_cast<uint32_t>(auth_len_));
  if (r != 0) {
    return absl::AbortedError(fmt::format("cipher_crypt failed: {}", ssh_err(r)));
  }

  in.drain(packlen + aad_len_ + auth_len_);
  out.add(out_data.data(), out_data.size());

  return absl::OkStatus();
}

namespace {
void generateKeyMaterial(bytes& out, char tag, KexResult* kex_result) {
  // translated from go ssh/transport.go
  bytes digestsSoFar;

  using namespace std::placeholders;
  while (out.size() < out.capacity()) {
    size_t digest_size;
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

std::unique_ptr<PacketCipher> newPacketCipher(direction_t d_read, direction_t d_write,
                                              KexResult* kex_result) {
  if (cipherModes.contains(kex_result->algorithms.r.cipher) &&
      cipherModes.contains(kex_result->algorithms.w.cipher)) {

    const auto& readMode = cipherModes.at(kex_result->algorithms.r.cipher);
    const auto& writeMode = cipherModes.at(kex_result->algorithms.w.cipher);

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

    return std::make_unique<PacketCipher>(readMode.create(readIv, readKey, ModeRead),
                                          writeMode.create(writeIv, writeKey, ModeWrite));
  }
  throw EnvoyException("unsupported algorithm"); // shouldn't get here ideally
}

size_t PacketCipher::blockSize(Mode mode) {
  switch (mode) {
  case ModeRead:
    return read_->blockSize();
  case ModeWrite:
    return write_->blockSize();
  }
  throw EnvoyException("unknown mode");
}

size_t PacketCipher::aadSize(Mode mode) {
  switch (mode) {
  case ModeRead:
    return read_->aadSize();
  case ModeWrite:
    return write_->aadSize();
  }
  throw EnvoyException("unknown mode");
}

size_t AEADPacketCipher::blockSize() {
  return block_len_;
};
size_t AEADPacketCipher::aadSize() {
  return aad_len_;
};

std::unique_ptr<PacketCipher> newUnencrypted() {
  return std::make_unique<PacketCipher>(std::make_unique<NoCipher>(), std::make_unique<NoCipher>());
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec