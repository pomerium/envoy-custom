#pragma once

#include <concepts>
#include <cstdint>
#include <type_traits>
#include <string>
#include <utility>

#include "source/common/static_string.h"

#include "source/common/status.h"
#include "source/common/types.h"
#include "source/extensions/filters/network/ssh/wire/common.h"
#include "source/extensions/filters/network/ssh/wire/encoding.h"
#include "source/extensions/filters/network/ssh/wire/field.h"
#include "source/extensions/filters/network/ssh/wire/key_field.h"
#include "source/extensions/filters/network/ssh/wire/message_types.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"

namespace wire::fxp {

// https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02

struct PosixRenameExtension final : SubMsg<SshMessageType::FxpInit, "posix-rename@openssh.com"> {
  field<std::string, LengthPrefixed> version;
};

struct StatvfsExtension final : SubMsg<SshMessageType::FxpInit, "statvfs@openssh.com"> {
  field<std::string, LengthPrefixed> version;
};

struct FstatvfsExtension final : SubMsg<SshMessageType::FxpInit, "fstatvfs@openssh.com"> {
  field<std::string, LengthPrefixed> version;
};

struct HardlinkExtension final : SubMsg<SshMessageType::FxpInit, "hardlink@openssh.com"> {
  field<std::string, LengthPrefixed> version;
};

struct FsyncExtension final : SubMsg<SshMessageType::FxpInit, "fsync@openssh.com"> {
  field<std::string, LengthPrefixed> version;
};

using InitExtension = BasicExtension<PosixRenameExtension,
                                     StatvfsExtension,
                                     FstatvfsExtension,
                                     HardlinkExtension,
                                     FsyncExtension>;

#define SSH_FILEXFER_ATTR_SIZE 0x00000001
#define SSH_FILEXFER_ATTR_UIDGID 0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS 0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME 0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED 0x80000000

struct placeholderExtension final : SubMsg<SshMessageType::FxpAttrs, "-"> {};

using FileAttrExtension = BasicExtension<placeholderExtension>;

struct Attrs {
  field<uint32_t> flags;
  field<uint64_t> size;
  field<uint32_t> uid;
  field<uint32_t> gid;
  field<uint32_t> permissions;
  field<uint32_t> atime;
  field<uint32_t> mtime;
  field<std::vector<FileAttrExtension>, EncodingOptions::ListSizePrefixed> extended_data;

  friend size_t read(Envoy::Buffer::Instance& buffer, Attrs& ext, size_t payload_size) {
    size_t n = 0;
    auto decodeIf = [&](bool should_decode, auto&... fields) {
      if (!should_decode) {
        return;
      }
      auto r = decodeSequence(buffer, payload_size - n, fields...);
      if (!r.ok()) {
        throw Envoy::EnvoyException(fmt::format("error decoding attrs: {}", statusToString(r.status())));
      }
      n += *r;
    };
    decodeIf(true, ext.flags);
    decodeIf((ext.flags & SSH_FILEXFER_ATTR_SIZE) != 0, ext.size);
    decodeIf((ext.flags & SSH_FILEXFER_ATTR_UIDGID) != 0, ext.uid, ext.gid);
    decodeIf((ext.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0, ext.permissions);
    decodeIf((ext.flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0, ext.atime, ext.mtime);
    decodeIf((ext.flags & SSH_FILEXFER_ATTR_EXTENDED) != 0, ext.extended_data);
    return n;
  }

  friend size_t write(Envoy::Buffer::Instance& buffer, const Attrs& ext) {
    size_t n = 0;
    auto encodeIf = [&](bool should_encode, auto&... fields) {
      if (!should_encode) {
        return;
      }
      auto r = encodeSequence(buffer, fields...);
      if (!r.ok()) {
        throw Envoy::EnvoyException(fmt::format("error encoding attrs: {}", statusToString(r.status())));
      }
      n += *r;
    };
    encodeIf(true, ext.flags);
    encodeIf((ext.flags & SSH_FILEXFER_ATTR_SIZE) != 0, ext.size);
    encodeIf((ext.flags & SSH_FILEXFER_ATTR_UIDGID) != 0, ext.uid, ext.gid);
    encodeIf((ext.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0, ext.permissions);
    encodeIf((ext.flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0, ext.atime, ext.mtime);
    encodeIf((ext.flags & SSH_FILEXFER_ATTR_EXTENDED) != 0, ext.extended_data);
    if (n >= MaxPacketSize) {
      throw Envoy::EnvoyException("message too large");
    }
    return n;
  }
};

struct InitMsg : Msg<SshMessageType::FxpInit> {
  field<uint32_t> version;
  field<std::vector<InitExtension>> extension_data;
};

struct VersionMsg final : Msg<SshMessageType::FxpVersion> {
  field<uint32_t> id;
  field<std::vector<InitExtension>> extension_data;
};

struct OpenMsg final : Msg<SshMessageType::FxpOpen> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> filename;
  field<uint32_t> pflags;
  field<Attrs> attrs;
};

struct CloseMsg final : Msg<SshMessageType::FxpClose> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> handle;
};

struct ReadMsg final : Msg<SshMessageType::FxpRead> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> handle;
  field<uint64_t> offset;
  field<uint32_t> len;
};

struct WriteMsg final : Msg<SshMessageType::FxpWrite> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> handle;
  field<uint64_t> offset;
  field<bytes, LengthPrefixed> data;
};

struct LstatMsg final : Msg<SshMessageType::FxpLstat> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> path;
};

struct FstatMsg final : Msg<SshMessageType::FxpFstat> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> handle;
};

struct SetstatMsg final : Msg<SshMessageType::FxpSetstat> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> path;
  field<Attrs> attrs;
};

struct FsetstatMsg final : Msg<SshMessageType::FxpFsetstat> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> handle;
  field<Attrs> attrs;
};

struct OpendirMsg final : Msg<SshMessageType::FxpOpendir> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> path;
};

struct ReaddirMsg final : Msg<SshMessageType::FxpReaddir> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> handle;
};

struct RemoveMsg final : Msg<SshMessageType::FxpRemove> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> filename;
};

struct MkdirMsg final : Msg<SshMessageType::FxpMkdir> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> path;
  field<Attrs> attrs;
};

struct RmdirMsg final : Msg<SshMessageType::FxpRmdir> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> path;
};

struct RealpathMsg final : Msg<SshMessageType::FxpRealpath> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> path;
};

struct StatMsg final : Msg<SshMessageType::FxpStat> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> path;
};

struct RenameMsg final : Msg<SshMessageType::FxpRename> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> oldpath;
  field<std::string, LengthPrefixed> newpath;
};

struct ReadlinkMsg final : Msg<SshMessageType::FxpReadlink> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> path;
};

// NOTE: see https://www.sftp.net/spec/openssh-sftp-extensions.txt about field order
struct SymlinkMsg final : Msg<SshMessageType::FxpSymlink> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> targetpath;
  field<std::string, LengthPrefixed> linkpath;
};

#define SSH_FX_OK 0
#define SSH_FX_EOF 1
#define SSH_FX_NO_SUCH_FILE 2
#define SSH_FX_PERMISSION_DENIED 3
#define SSH_FX_FAILURE 4
#define SSH_FX_BAD_MESSAGE 5
#define SSH_FX_NO_CONNECTION 6
#define SSH_FX_CONNECTION_LOST 7
#define SSH_FX_OP_UNSUPPORTED 8

struct StatusMsg final : Msg<SshMessageType::FxpStatus> {
  field<uint32_t> id;
  field<uint32_t> status_code;
  field<std::string, LengthPrefixed> error_message;
  field<std::string, LengthPrefixed> language_tag;
};

struct HandleMsg final : Msg<SshMessageType::FxpHandle> {
  field<uint32_t> id;
  field<std::string, LengthPrefixed> handle;
};

struct DataMsg final : Msg<SshMessageType::FxpData> {
  field<uint32_t> id;
  field<bytes, LengthPrefixed> data;
};

struct Name {
  field<std::string, LengthPrefixed> filename;
  field<std::string, LengthPrefixed> longname;
  field<Attrs> attrs;

  friend size_t read(Envoy::Buffer::Instance& buffer, Name& name, size_t payload_size) {
    auto n = decodeSequence(buffer, payload_size, name.filename, name.longname, name.attrs);
    if (!n.ok()) {
      throw Envoy::EnvoyException(fmt::format("error decoding name: {}", statusToString(n.status())));
    }
    return *n;
  }
  friend size_t write(Envoy::Buffer::Instance& buffer, const Name& name) {
    auto n = encodeSequence(buffer, name.filename, name.longname, name.attrs);
    if (!n.ok()) {
      throw Envoy::EnvoyException(fmt::format("error encoding name: {}", statusToString(n.status())));
    }
    return *n;
  }
};

struct NameMsg final : Msg<SshMessageType::FxpName> {
  field<uint32_t> id;
  field<Name, ListSizePrefixed> names;
};

struct AttrsMsg final : Msg<SshMessageType::FxpAttrs> {
  field<uint32_t> id;
  field<Attrs> attrs;
};

struct PosixRenameMsg final : SubMsg<SshMessageType::FxpExtended, "posix-rename@openssh.com"> {
};

struct StatvfsMsg final : SubMsg<SshMessageType::FxpExtended, "statvfs@openssh.com"> {
};

struct FstatvfsMsg final : SubMsg<SshMessageType::FxpExtended, "fstatvfs@openssh.com"> {
};

struct HardlinkMsg final : SubMsg<SshMessageType::FxpExtended, "hardlink@openssh.com"> {
};

struct FsyncMsg final : SubMsg<SshMessageType::FxpExtended, "fsync@openssh.com"> {
};

struct ExtendedMsg final : Msg<SshMessageType::FxpExtended> {
  field<uint32_t> id;
  using message_type = sub_message<PosixRenameMsg,
                                   StatvfsMsg,
                                   FstatvfsMsg,
                                   HardlinkMsg,
                                   FsyncMsg>;
  [[no_unique_address]] key_field<message_type> message_key;
  message_type message;
};

struct ExtendedReplyMsg final : Msg<SshMessageType::FxpExtendedReply> {
  field<uint32_t> id;
};

} // namespace wire::fxp