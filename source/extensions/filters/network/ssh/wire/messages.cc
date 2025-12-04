#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/common/status.h"

namespace wire {

// KexInitMessage
absl::StatusOr<size_t> KexInitMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   cookie,
                   kex_algorithms,
                   server_host_key_algorithms,
                   encryption_algorithms_client_to_server,
                   encryption_algorithms_server_to_client,
                   mac_algorithms_client_to_server,
                   mac_algorithms_server_to_client,
                   compression_algorithms_client_to_server,
                   compression_algorithms_server_to_client,
                   languages_client_to_server,
                   languages_server_to_client,
                   first_kex_packet_follows,
                   reserved);
}
absl::StatusOr<size_t> KexInitMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   cookie,
                   kex_algorithms,
                   server_host_key_algorithms,
                   encryption_algorithms_client_to_server,
                   encryption_algorithms_server_to_client,
                   mac_algorithms_client_to_server,
                   mac_algorithms_server_to_client,
                   compression_algorithms_client_to_server,
                   compression_algorithms_server_to_client,
                   languages_client_to_server,
                   languages_server_to_client,
                   first_kex_packet_follows,
                   reserved);
}

// KexEcdhInitMessage
absl::StatusOr<size_t> KexEcdhInitMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   client_pub_key);
}
absl::StatusOr<size_t> KexEcdhInitMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   client_pub_key);
}

// KexEcdhReplyMsg
absl::StatusOr<size_t> KexEcdhReplyMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   host_key,
                   ephemeral_pub_key,
                   signature);
}
absl::StatusOr<size_t> KexEcdhReplyMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   host_key,
                   ephemeral_pub_key,
                   signature);
}

// KexHybridInitMessage
absl::StatusOr<size_t> KexHybridInitMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   client_init);
}
absl::StatusOr<size_t> KexHybridInitMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   client_init);
}

// KexHybridReplyMsg
absl::StatusOr<size_t> KexHybridReplyMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   host_key,
                   server_reply,
                   signature);
}
absl::StatusOr<size_t> KexHybridReplyMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   host_key,
                   server_reply,
                   signature);
}

// ServiceRequestMsg
absl::StatusOr<size_t> ServiceRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   service_name);
}
absl::StatusOr<size_t> ServiceRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   service_name);
}

// ServiceAcceptMsg
absl::StatusOr<size_t> ServiceAcceptMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   service_name);
}
absl::StatusOr<size_t> ServiceAcceptMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   service_name);
}

// X11ChannelOpenMsg
absl::StatusOr<size_t> X11ChannelOpenMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeSequence(buffer, payload_size,
                        originator_address,
                        originator_port);
}
absl::StatusOr<size_t> X11ChannelOpenMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer,
                        originator_address,
                        originator_port);
}

// ForwardedTcpipChannelOpenMsg
absl::StatusOr<size_t> ForwardedTcpipChannelOpenMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeSequence(buffer, payload_size,
                        address_connected,
                        port_connected,
                        originator_address,
                        originator_port);
}
absl::StatusOr<size_t> ForwardedTcpipChannelOpenMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer,
                        address_connected,
                        port_connected,
                        originator_address,
                        originator_port);
}

// DirectTcpipChannelOpenMsg
absl::StatusOr<size_t> DirectTcpipChannelOpenMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeSequence(buffer, payload_size,
                        host_to_connect,
                        port_to_connect,
                        originator_address,
                        originator_port);
}
absl::StatusOr<size_t> DirectTcpipChannelOpenMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer,
                        host_to_connect,
                        port_to_connect,
                        originator_address,
                        originator_port);
}

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

// PtyReqChannelRequestMsg
absl::StatusOr<size_t> PtyReqChannelRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeSequence(buffer, payload_size,
                        term_env,
                        width_columns,
                        height_rows,
                        width_px,
                        height_px,
                        modes);
}
absl::StatusOr<size_t> PtyReqChannelRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer,
                        term_env,
                        width_columns,
                        height_rows,
                        width_px,
                        height_px,
                        modes);
}

// WindowDimensionChangeChannelRequestMsg
absl::StatusOr<size_t> WindowDimensionChangeChannelRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeSequence(buffer, payload_size,
                        width_columns,
                        height_rows,
                        width_px,
                        height_px);
}
absl::StatusOr<size_t> WindowDimensionChangeChannelRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer,
                        width_columns,
                        height_rows,
                        width_px,
                        height_px);
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

// ChannelOpenConfirmationMsg
absl::StatusOr<size_t> ChannelOpenConfirmationMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel,
                   sender_channel,
                   initial_window_size,
                   max_packet_size,
                   extra);
}
absl::StatusOr<size_t> ChannelOpenConfirmationMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel,
                   sender_channel,
                   initial_window_size,
                   max_packet_size,
                   extra);
}

// ChannelOpenFailureMsg
absl::StatusOr<size_t> ChannelOpenFailureMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel,
                   reason_code,
                   description,
                   language_tag);
}
absl::StatusOr<size_t> ChannelOpenFailureMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel,
                   reason_code,
                   description,
                   language_tag);
}

// ChannelWindowAdjustMsg
absl::StatusOr<size_t> ChannelWindowAdjustMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel,
                   bytes_to_add);
}
absl::StatusOr<size_t> ChannelWindowAdjustMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel,
                   bytes_to_add);
}

// ChannelDataMsg
absl::StatusOr<size_t> ChannelDataMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel,
                   data);
}
absl::StatusOr<size_t> ChannelDataMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel,
                   data);
}

// ChannelExtendedDataMsg
absl::StatusOr<size_t> ChannelExtendedDataMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel,
                   data_type_code,
                   data);
}
absl::StatusOr<size_t> ChannelExtendedDataMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel,
                   data_type_code,
                   data);
}

// ChannelEOFMsg
absl::StatusOr<size_t> ChannelEOFMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel);
}
absl::StatusOr<size_t> ChannelEOFMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel);
}

// ChannelCloseMsg
absl::StatusOr<size_t> ChannelCloseMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel);
}
absl::StatusOr<size_t> ChannelCloseMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel);
}

// ChannelSuccessMsg
absl::StatusOr<size_t> ChannelSuccessMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel);
}
absl::StatusOr<size_t> ChannelSuccessMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel);
}

// ChannelFailureMsg
absl::StatusOr<size_t> ChannelFailureMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   recipient_channel);
}
absl::StatusOr<size_t> ChannelFailureMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   recipient_channel);
}

// HostKeysProveRequestMsg
absl::StatusOr<size_t> HostKeysProveRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t len) noexcept {
  return decodeSequence(buffer, len, hostkeys);
}
absl::StatusOr<size_t> HostKeysProveRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer, hostkeys);
}

// HostKeysMsg
absl::StatusOr<size_t> HostKeysMsg::decode(Envoy::Buffer::Instance& buffer, size_t len) noexcept {
  return decodeSequence(buffer, len, hostkeys);
}
absl::StatusOr<size_t> HostKeysMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer, hostkeys);
}

// TcpipForwardMsg
absl::StatusOr<size_t> TcpipForwardMsg::decode(Envoy::Buffer::Instance& buffer, size_t len) noexcept {
  return decodeSequence(buffer, len, remote_address, remote_port);
}
absl::StatusOr<size_t> TcpipForwardMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer, remote_address, remote_port);
}

// CancelTcpipForwardMsg
absl::StatusOr<size_t> CancelTcpipForwardMsg::decode(Envoy::Buffer::Instance& buffer, size_t len) noexcept {
  return decodeSequence(buffer, len, remote_address, remote_port);
}
absl::StatusOr<size_t> CancelTcpipForwardMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer, remote_address, remote_port);
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

// HostKeysProveResponseMsg
absl::StatusOr<size_t> HostKeysProveResponseMsg::decode(Envoy::Buffer::Instance& buffer, size_t len) noexcept {
  return decodeSequence(buffer, len, signatures);
}
absl::StatusOr<size_t> HostKeysProveResponseMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer, signatures);
};

// TcpipForwardResponseMsg
absl::StatusOr<size_t> TcpipForwardResponseMsg::decode(Envoy::Buffer::Instance& buffer, size_t len) noexcept {
  return decodeSequence(buffer, len, server_port);
}
absl::StatusOr<size_t> TcpipForwardResponseMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer, server_port);
};

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

// IgnoreMsg
absl::StatusOr<size_t> IgnoreMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   data);
}
absl::StatusOr<size_t> IgnoreMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   data);
}

// DebugMsg
absl::StatusOr<size_t> DebugMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   always_display,
                   message,
                   language_tag);
}
absl::StatusOr<size_t> DebugMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   always_display,
                   message,
                   language_tag);
}

// UnimplementedMsg
absl::StatusOr<size_t> UnimplementedMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   sequence_number);
}
absl::StatusOr<size_t> UnimplementedMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   sequence_number);
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

// KeyboardInteractiveUserAuthRequestMsg
absl::StatusOr<size_t> KeyboardInteractiveUserAuthRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeSequence(buffer, payload_size,
                        language_tag,
                        submethods);
}
absl::StatusOr<size_t> KeyboardInteractiveUserAuthRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeSequence(buffer,
                        language_tag,
                        submethods);
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

// UserAuthInfoRequestMsg
absl::StatusOr<size_t> UserAuthInfoRequestMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   name,
                   instruction,
                   language_tag,
                   prompts);
}
absl::StatusOr<size_t> UserAuthInfoRequestMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   name,
                   instruction,
                   language_tag,
                   prompts);
}

// UserAuthInfoResponseMsg
absl::StatusOr<size_t> UserAuthInfoResponseMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   responses);
}
absl::StatusOr<size_t> UserAuthInfoResponseMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   responses);
}

// UserAuthBannerMsg
absl::StatusOr<size_t> UserAuthBannerMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   message,
                   language_tag);
}
absl::StatusOr<size_t> UserAuthBannerMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   message,
                   language_tag);
}

// UserAuthFailureMsg
absl::StatusOr<size_t> UserAuthFailureMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   methods,
                   partial);
}
absl::StatusOr<size_t> UserAuthFailureMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   methods,
                   partial);
}

// DisconnectMsg
absl::StatusOr<size_t> DisconnectMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   reason_code,
                   description,
                   language_tag);
}
absl::StatusOr<size_t> DisconnectMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   reason_code,
                   description,
                   language_tag);
}

// UserAuthPubKeyOkMsg
absl::StatusOr<size_t> UserAuthPubKeyOkMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   public_key_alg,
                   public_key);
}
absl::StatusOr<size_t> UserAuthPubKeyOkMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   public_key_alg,
                   public_key);
}

// ServerSigAlgsExtension
absl::StatusOr<size_t> ServerSigAlgsExtension::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return public_key_algorithms_accepted.decode(buffer, payload_size);
}
absl::StatusOr<size_t> ServerSigAlgsExtension::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return public_key_algorithms_accepted.encode(buffer);
}

// PingExtension
absl::StatusOr<size_t> PingExtension::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return version.decode(buffer, payload_size);
}
absl::StatusOr<size_t> PingExtension::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return version.encode(buffer);
}

// ExtInfoInAuthExtension
absl::StatusOr<size_t> ExtInfoInAuthExtension::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return version.decode(buffer, payload_size);
}
absl::StatusOr<size_t> ExtInfoInAuthExtension::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return version.encode(buffer);
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

// ExtInfoMsg
absl::StatusOr<size_t> ExtInfoMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   extensions);
}
absl::StatusOr<size_t> ExtInfoMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   extensions);
}

// PingMsg
absl::StatusOr<size_t> PingMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   data);
}
absl::StatusOr<size_t> PingMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   data);
}

// PongMsg
absl::StatusOr<size_t> PongMsg::decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept {
  return decodeMsg(buffer, type, payload_size,
                   data);
}
absl::StatusOr<size_t> PongMsg::encode(Envoy::Buffer::Instance& buffer) const noexcept {
  return encodeMsg(buffer, type,
                   data);
}

template struct BasicMessage<detail::top_level_message>;

} // namespace wire