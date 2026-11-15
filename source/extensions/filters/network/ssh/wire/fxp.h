#pragma once

#include <cstdint>
#include <string>

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

static constexpr uint32_t SSH_FILEXFER_ATTR_SIZE = 0x00000001;
static constexpr uint32_t SSH_FILEXFER_ATTR_UIDGID = 0x00000002;
static constexpr uint32_t SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
static constexpr uint32_t SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008;
static constexpr uint32_t SSH_FILEXFER_ATTR_EXTENDED = 0x80000000;

struct placeholderExtension final : SubMsg<SshMessageType::FxpAttrs, "-"> {};

using FileAttrExtension = BasicExtension<placeholderExtension>;

struct Attrs {
  selector_field<uint32_t> flags;
  optional_field<uint64_t, SSH_FILEXFER_ATTR_SIZE> size;
  optional_field<uint32_t, SSH_FILEXFER_ATTR_UIDGID> uid;
  optional_field<uint32_t, SSH_FILEXFER_ATTR_UIDGID> gid;
  optional_field<uint32_t, SSH_FILEXFER_ATTR_PERMISSIONS> permissions;
  optional_field<uint32_t, SSH_FILEXFER_ATTR_ACMODTIME> atime;
  optional_field<uint32_t, SSH_FILEXFER_ATTR_ACMODTIME> mtime;
  optional_field<std::vector<FileAttrExtension>, SSH_FILEXFER_ATTR_EXTENDED, EncodingOptions::ListSizePrefixed> extended_data;

  constexpr bool operator==(const Attrs&) const = default;
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

  constexpr bool operator==(const Name&) const = default;
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
  field<std::string, LengthPrefixed> oldpath;
  field<std::string, LengthPrefixed> newpath;
};

struct StatvfsMsg final : SubMsg<SshMessageType::FxpExtended, "statvfs@openssh.com"> {
  field<std::string, LengthPrefixed> path;
};

struct FstatvfsMsg final : SubMsg<SshMessageType::FxpExtended, "fstatvfs@openssh.com"> {
  field<std::string, LengthPrefixed> handle;
};

struct HardlinkMsg final : SubMsg<SshMessageType::FxpExtended, "hardlink@openssh.com"> {
  field<std::string, LengthPrefixed> oldpath;
  field<std::string, LengthPrefixed> newpath;
};

struct FsyncMsg final : SubMsg<SshMessageType::FxpExtended, "fsync@openssh.com"> {
  field<std::string, LengthPrefixed> handle;
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

#define SSH_FXE_STATVFS_ST_RDONLY 0x1 /* read-only */
#define SSH_FXE_STATVFS_ST_NOSUID 0x2 /* no setuid */

struct StatvfsExtendedReplyMsg final : SubMsg<SshMessageType::FxpExtendedReply, "statvfs", Omit> {
  field<uint64_t> f_bsize;
  field<uint64_t> f_frsize;
  field<uint64_t> f_blocks;
  field<uint64_t> f_bfree;
  field<uint64_t> f_bavail;
  field<uint64_t> f_files;
  field<uint64_t> f_ffree;
  field<uint64_t> f_favail;
  field<uint64_t> f_fsid;
  field<uint64_t> f_flag;
  field<uint64_t> f_namemax;
};

struct ExtendedReplyMsg final : Msg<SshMessageType::FxpExtendedReply> {
  field<uint32_t> id;
  using reply_type = sub_message<StatvfsExtendedReplyMsg>;
  [[no_unique_address]] key_field<reply_type> reply_key;
  reply_type reply;
};

namespace detail {
using top_level_message = sub_message< // Message ID
  InitMsg,                             // 1
  VersionMsg,                          // 2
  OpenMsg,                             // 3
  CloseMsg,                            // 4
  ReadMsg,                             // 5
  WriteMsg,                            // 6
  LstatMsg,                            // 7
  FstatMsg,                            // 8
  SetstatMsg,                          // 9
  FsetstatMsg,                         // 10
  OpendirMsg,                          // 11
  ReaddirMsg,                          // 12
  RemoveMsg,                           // 13
  MkdirMsg,                            // 14
  RmdirMsg,                            // 15
  RealpathMsg,                         // 16
  StatMsg,                             // 17
  RenameMsg,                           // 18
  ReadlinkMsg,                         // 19
  SymlinkMsg,                          // 20
  StatusMsg,                           // 101
  HandleMsg,                           // 102
  DataMsg,                             // 103
  NameMsg,                             // 104
  AttrsMsg,                            // 105
  ExtendedMsg,                         // 200
  ExtendedReplyMsg>;                   // 201

static_assert(std::regular<top_level_message>);

} // namespace detail

using Message = BasicMessage<fxp::detail::top_level_message>;
using MessagePtr = std::unique_ptr<Message>;

} // namespace wire::fxp