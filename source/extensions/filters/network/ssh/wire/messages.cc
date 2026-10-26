#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/common/status.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"

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

template struct BasicMessage<detail::top_level_message>;

} // namespace wire