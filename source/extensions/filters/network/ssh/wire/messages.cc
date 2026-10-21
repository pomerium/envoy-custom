#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/common/status.h"

namespace wire {

// PubKeyUserAuthRequestMsg (non-standard)
absl::StatusOr<size_t> PubKeyUserAuthRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  auto n = decodeSequence(buffer, payload_size,
                          has_signature,
                          public_key_alg,
                          public_key);
  if (n.ok() && has_signature) {
    auto sn = signature.decode(buffer, payload_size - *n);
    if (!sn.ok()) {
      return sn;
    }
    return *n + *sn;
  }
  return n;
}

absl::StatusOr<size_t> PubKeyUserAuthRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  auto n = encodeSequence(buffer,
                          has_signature,
                          public_key_alg,
                          public_key);
  if (n.ok() && has_signature) {
    return *n + *signature.encode(buffer);
  }
  return n;
}

// UserAuthInfoPrompt
size_t read(Envoy::Buffer::Instance& buffer, UserAuthInfoPrompt& prompt, size_t payload_size) {
  auto n = decodeSequence(buffer, payload_size, prompt.prompt, prompt.echo);
  if (!n.ok()) {
    throw Envoy::EnvoyException(fmt::format("error decoding UserAuthInfoPrompt: {}", n.status().message()));
  }
  return *n;
}
size_t write(Envoy::Buffer::Instance& buffer, const UserAuthInfoPrompt& prompt) {
  auto n = encodeSequence(buffer, prompt.prompt, prompt.echo);
  if (!n.ok()) {
    throw Envoy::EnvoyException(fmt::format("error encoding UserAuthInfoPrompt: {}", n.status().message()));
  }
  return *n;
}

// Extension
size_t read(Envoy::Buffer::Instance& buffer, Extension& ext, size_t payload_size) {
  size_t n = 0;
  if (auto r = ext.extension.key_field().decode(buffer, payload_size); !r.ok()) {
    throw Envoy::EnvoyException(fmt::format("error decoding extension name: {}", statusToString(r.status())));
  } else {
    n += *r;
  }
  // extension values are always strings, and thus will always have a length prefix
  auto extDataLen = buffer.peekBEInt<uint32_t>() + 4uz;
  if (extDataLen > payload_size) {
    throw Envoy::EnvoyException(fmt::format("error decoding extension: invalid message length: {}", extDataLen));
  }
  if (auto r = ext.extension.decode(buffer, extDataLen); !r.ok()) {
    throw Envoy::EnvoyException(fmt::format("error decoding extension: {}", statusToString(r.status())));
  } else {
    n += *r;
  }
  return n;
}
size_t write(Envoy::Buffer::Instance& buffer, const Extension& ext) {
  auto n = encodeSequence(buffer, ext.extension_key, ext.extension);
  if (!n.ok()) {
    throw Envoy::EnvoyException(fmt::format("error encoding extension: {}", statusToString(n.status())));
  }
  return *n;
}

template struct BasicMessage<detail::top_level_message>;

} // namespace wire