#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/common/status.h"

namespace wire {

// ChannelOpenMsg
absl::StatusOr<size_t> ChannelOpenMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   request.key_field(),
                   sender_channel,
                   initial_window_size,
                   max_packet_size,
                   request);
}
absl::StatusOr<size_t> ChannelOpenMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   request.key_field(),
                   sender_channel,
                   initial_window_size,
                   max_packet_size,
                   request);
}

// ChannelRequestMsg
absl::StatusOr<size_t> ChannelRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel,
                   request.key_field(),
                   want_reply,
                   request);
}
absl::StatusOr<size_t> ChannelRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel,
                   request.key_field(),
                   want_reply,
                   request);
}

// GlobalRequestMsg
absl::StatusOr<size_t> GlobalRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   request.key_field(),
                   want_reply,
                   request);
}
absl::StatusOr<size_t> GlobalRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   request.key_field(),
                   want_reply,
                   request);
}

// GlobalRequestSuccessMsg (non-standard)
absl::StatusOr<size_t> GlobalRequestSuccessMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   wire::tags::no_validation{},
                   response);
}
absl::StatusOr<size_t> GlobalRequestSuccessMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   wire::tags::no_validation{},
                   response);
}

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

// UserAuthRequestMsg
absl::StatusOr<size_t> UserAuthRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   username,
                   service_name,
                   request.key_field(),
                   request);
}
absl::StatusOr<size_t> UserAuthRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   username,
                   service_name,
                   request.key_field(),
                   request);
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
  auto n = encodeSequence(buffer, ext.extension.key_field(), ext.extension);
  if (!n.ok()) {
    throw Envoy::EnvoyException(fmt::format("error encoding extension: {}", statusToString(n.status())));
  }
  return *n;
}

template struct BasicMessage<detail::top_level_message>;

} // namespace wire