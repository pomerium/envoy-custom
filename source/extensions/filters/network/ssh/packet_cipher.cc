#include "source/extensions/filters/network/ssh/packet_cipher.h"

#include <algorithm>
#include <iterator>

#include "source/extensions/filters/network/ssh/kex.h"

extern "C" {
#include "openssh/openbsd-compat/sha2.h"
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

AEADPacketCipher::AEADPacketCipher(const char* cipher_name, bytearray /*iv*/, bytearray key,
                                   Mode mode) {
  auto cipher = cipher_by_name(cipher_name);
  block_len_ = cipher_blocksize(cipher);
  auth_len_ = cipher_authlen(cipher);
  iv_len_ = cipher_ivlen(cipher);
  aad_len_ = 4;
  sshcipher_ctx* cipher_ctx;
  cipher_init(&cipher_ctx, cipher, key.data(), key.size(), nullptr, 0, mode);
  ctx_.reset(cipher_ctx);
}

absl::Status AEADPacketCipher::encryptPacket(uint32_t seqnum, Envoy::Buffer::Instance& out,
                                             Envoy::Buffer::Instance& in) {

  auto in_length = in.length();
  auto in_data = static_cast<uint8_t*>(in.linearize(in_length));
  uint32_t packlen = in_length;

  bytearray out_data;
  out_data.resize(packlen + auth_len_);

  auto r = cipher_crypt(ctx_.get(), seqnum, out_data.data(), in_data, packlen - aad_len_, aad_len_,
                        auth_len_);
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
  auto in_data = static_cast<uint8_t*>(in.linearize(in_length));
  uint32_t packlen = 0;
  if (cipher_get_length(ctx_.get(), &packlen, seqnum, in_data, in_length) != 0) {
    return absl::AbortedError("packet too small");
  }
  if (packlen < 5 || packlen > PACKET_MAX_SIZE) {
    for (auto test : std::vector<uint32_t>{seqnum - 1, seqnum + 1, seqnum - 2, seqnum + 2, 0}) {
      if (cipher_get_length(ctx_.get(), &packlen, test, in_data, in_length) == 0 &&
          packlen < PACKET_MAX_SIZE) {
        ENVOY_LOG(warn, "sequence number drift: packet decrypts with seqnr={}, but ours is {}",
                  test, seqnum);
      }
    }
    return absl::AbortedError(fmt::format("bad packet length: {} (seqnr {})", packlen, seqnum));
  }
  if (packlen % block_len_ != 0) {
    return absl::AbortedError(fmt::format("padding error: need {} block {} mod {}", packlen,
                                          block_len_, packlen % block_len_));
  }
  if (in_length < aad_len_ + packlen + auth_len_) {
    return absl::OkStatus(); // incomplete packet
  }

  bytearray out_data;
  out_data.resize(packlen + aad_len_);

  auto r = cipher_crypt(ctx_.get(), seqnum, out_data.data(), in_data, packlen, aad_len_, auth_len_);
  if (r != 0) {
    return absl::AbortedError(fmt::format("cipher_crypt failed: {}", ssh_err(r)));
  }

  in.drain(packlen + aad_len_ + auth_len_);
  out.add(out_data.data(), out_data.size());

  return absl::OkStatus();
}

void generateKeyMaterial(bytearray& out, const bytearray& tag, kex_result_t* kex_result) {
  // translated from go ssh/transport.go
  bytearray digestsSoFar;
  std::string x;

  using namespace std::placeholders;
  while (out.size() < out.capacity()) {
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
      break;
    case SHA512:
      SHA512Init(&hash_ctx);
      write = std::bind(&SHA512Update, &hash_ctx, _1, _2);
      sum = std::bind(&SHA512Final, _1, &hash_ctx);
      digest_size = 64;
      break;
    default:
      throw EnvoyException("unsupported hash algorithm");
    }
    bytearray encoded_k;
    kex_result->EncodeSharedSecret(encoded_k);
    write(encoded_k.data(), encoded_k.size());
    write(kex_result->H.data(), kex_result->H.size());
    if (digestsSoFar.size() == 0) {
      write(tag.data(), tag.size());
      write(kex_result->SessionID.data(), kex_result->SessionID.size());
    } else {
      write(digestsSoFar.data(), digestsSoFar.size());
    }
    bytearray digest(digest_size, 0);
    sum(digest.data());
    auto toCopy = std::min(out.capacity() - out.size(), digest.size());
    if (toCopy > 0) {
      std::copy_n(digest.begin(), toCopy, std::back_inserter(out));
      std::copy(digest.begin(), digest.end(), std::back_inserter(digestsSoFar));
    }
  }
}

std::unique_ptr<PacketCipher> NewPacketCipher(direction_t d_read, direction_t d_write,
                                              kex_result_t* kex_result) {
  if (cipherModes.contains(kex_result->Algorithms.r.cipher) &&
      cipherModes.contains(kex_result->Algorithms.w.cipher)) {

    auto readMode = cipherModes.at(kex_result->Algorithms.r.cipher);
    auto writeMode = cipherModes.at(kex_result->Algorithms.w.cipher);

    bytearray readIv;
    readIv.reserve(readMode.ivSize);
    generateKeyMaterial(readIv, d_read.iv_tag, kex_result);
    bytearray readKey;
    readKey.reserve(readMode.keySize);
    generateKeyMaterial(readKey, d_read.key_tag, kex_result);

    // todo: non-aead ciphers?

    bytearray writeIv;
    writeIv.reserve(writeMode.ivSize);
    generateKeyMaterial(writeIv, d_write.iv_tag, kex_result);
    bytearray writeKey;
    writeKey.reserve(writeMode.keySize);
    generateKeyMaterial(writeKey, d_write.key_tag, kex_result);

    return std::make_unique<PacketCipher>(readMode.create(readIv, readKey, MODE_READ),
                                          writeMode.create(writeIv, writeKey, MODE_WRITE));
  }
  throw EnvoyException("unsupported algorithm"); // shouldn't get here ideally
}

size_t PacketCipher::blockSize(Mode mode) {
  switch (mode) {
  case MODE_READ:
    return read_->blockSize();
  case MODE_WRITE:
    return write_->blockSize();
  }
  throw EnvoyException("unknown mode");
}

size_t PacketCipher::aadSize(Mode mode) {
  switch (mode) {
  case MODE_READ:
    return read_->aadSize();
  case MODE_WRITE:
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

std::unique_ptr<PacketCipher> NewUnencrypted() {
  return std::make_unique<PacketCipher>(std::make_unique<NoCipher>(), std::make_unique<NoCipher>());
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec