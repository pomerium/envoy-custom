#include "source/extensions/filters/network/ssh/version_exchange.h"
#include <ranges>

extern "C" {
#include "openssh/ssh.h"
}

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

VersionExchanger::VersionExchanger(TransportCallbacks& transport_callbacks,
                                   VersionExchangeCallbacks& version_exchange_callbacks,
                                   VersionExchangeMode mode)
    : transport_(transport_callbacks),
      version_exchange_callbacks_(version_exchange_callbacks),
      is_server_(mode == VersionExchangeMode::Server) {}

static constexpr size_t MaxBannerLines = SSH_MAX_PRE_BANNER_LINES;
static constexpr size_t MaxBannerLineLength = SSH_MAX_BANNER_LEN;
static constexpr size_t MaxVersionLineLength = 255;

// Arbitrary limit to keep things reasonably small. Openssh has an 8MB limit, which seems high.
static constexpr size_t MaxVersionExchangeBytes = 16384;

// Implements https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
//
// NB: the RFC mentions a maximum version string length of 255, but the wording is ambiguous about
// constraints on banner lines. Openssh appears to ignore the RFC here, instead limiting the total
// input to 1024 lines of at most 8192 bytes, which includes the version string.
// For comparison, the Go implementation limits the total input to 255 bytes, including banner and
// version string - this seems incorrect.
// My interpretation of the RFC is that the version string has a 255 byte limit, and limits on the
// banner lines are implementation defined. We will impose a 16KB limit on the total banner+version
// bytes that will be processed, then validate the banner using the openssh constraints, as well as
// limit the version string to 255 bytes.
// The use cases for including such a banner before the version string could include displaying
// legal notices etc., so ideally we should keep track of any banner string we receive from the
// upstream to send as either an authentication banner message or a disconnect mesage to the
// downstream client, depending on whether the upstream disconnects after sending the banner.
absl::StatusOr<size_t> VersionExchanger::readVersion(Envoy::Buffer::Instance& buffer) {
  if (did_read_version_) {
    return absl::FailedPreconditionError("version already read");
  }
  if (buffer.length() > MaxVersionExchangeBytes) {
    return absl::InvalidArgumentError("no ssh identification string received");
  } else if (buffer.length() < 4) { // "SSH-"
    // incomplete version
    return 0;
  }
  ssize_t versionStringStartIndex = -1;
  ssize_t versionStringEndIndex = -1;
  if (buffer.startsWith("SSH-")) {
    versionStringStartIndex = 0;
  } else if (!is_server_) {
    versionStringStartIndex = buffer.search("\nSSH-", 5, 0, buffer.length());
    if (versionStringStartIndex == -1) {
      // incomplete version
      return 0;
    }
    versionStringStartIndex++; // skip the '\n' matched from the previous line
  } else {
    // only the client can receive banner text
    return absl::InvalidArgumentError("invalid version string");
  }
  ASSERT(versionStringStartIndex != -1);

  bytes banner;
  if (versionStringStartIndex > 0) {
    banner.resize(versionStringStartIndex);
    buffer.copyOut(0, banner.size(), banner.data());
    if (auto stat = validateBanner(banner); !stat.ok()) {
      return stat;
    }
  }

  versionStringEndIndex = buffer.search("\n", 1, versionStringStartIndex, MaxVersionLineLength);
  if (versionStringEndIndex == -1) {
    if (buffer.length() - versionStringStartIndex >= MaxVersionLineLength) { // no \n found in the next 255 bytes
      return absl::InvalidArgumentError("version string too long");
    } else {
      // incomplete version
      return 0;
    }
  }
  ASSERT(versionStringEndIndex != -1);

  bytes version;
  version.resize(versionStringEndIndex - versionStringStartIndex + 1); // include the newline
  buffer.copyOut(versionStringStartIndex, version.size(), version.data());
  if (auto stat = validateVersion(version); !stat.ok()) {
    return stat;
  }
  buffer.drain(versionStringEndIndex + 1);

  did_read_version_ = true;
  banner_text_ = std::move(banner);
  their_version_ = std::move(version);
  invokeCallbacksIfDone();

  return versionStringEndIndex + 1;
}

absl::StatusOr<size_t> VersionExchanger::writeVersion(std::string_view ours) {
  if (did_write_version_) {
    return absl::FailedPreconditionError("version already written");
  }
  did_write_version_ = true;

  our_version_ = to_bytes(ours);
  our_version_.push_back('\r');
  our_version_.push_back('\n');
  Envoy::Buffer::OwnedImpl w;
  wire::write(w, our_version_);
  auto n = w.length();
  transport_.writeToConnection(w);
  invokeCallbacksIfDone();
  return n;
}

void VersionExchanger::invokeCallbacksIfDone() {
  if (did_write_version_ && did_read_version_) {
    if (is_server_) {
      ASSERT(banner_text_.empty());
      version_exchange_callbacks_.onVersionExchangeCompleted(our_version_,   // server (us)
                                                             their_version_, // client
                                                             {});
    } else {
      version_exchange_callbacks_.onVersionExchangeCompleted(their_version_, // server
                                                             our_version_,   // client (us)
                                                             banner_text_);
    }
  }
}

static const auto InvalidChars = {'\0'_byte, '\r'_byte};
static const auto VersionPrefix = "SSH-2.0-"_bytes;

absl::Status VersionExchanger::validateBanner(const bytes& banner) const {
  size_t numLines = 0;
  for (auto line_subrange : std::views::split(banner, '\n'_byte)) {
    bytes_view line{line_subrange};
    if (++numLines > MaxBannerLines) {
      return absl::InvalidArgumentError("too many banner lines received");
    }
    if (line.size() > MaxBannerLineLength) {
      return absl::InvalidArgumentError("banner line too long");
    }
    if (line.back() == '\r') {
      line = line.subspan(0, line.size() - 1);
    }

    if (std::ranges::find_first_of(line, InvalidChars) != line.end()) {
      return absl::InvalidArgumentError("banner line contains invalid characters");
    }
  }
  return absl::OkStatus();
}

absl::Status VersionExchanger::validateVersion(const bytes& version) const {
  ASSERT(version.back() == '\n');
  if (!std::ranges::starts_with(version, VersionPrefix)) {
    return absl::InvalidArgumentError("unsupported protocol version");
  }
  // skip "SSH-2.0-" prefix and "\n" suffix
  auto version_view = bytes_view(version).subspan(VersionPrefix.size(),
                                                  version.size() - VersionPrefix.size() - 1);
  if (version_view.back() == '\r') {
    // The version string should end with \r\n, but both openssh and go are lenient here and allow
    // it to end only in \n, so we will do the same.
    version_view = version_view.first(version_view.size() - 1);
  }
  if (version_view.size() == 0 || // "SSH-2.0-"
      version_view[0] == ' ') {   // "SSH-2.0- -comment"
    // the 'softwareversion' string is not optional
    return absl::InvalidArgumentError("invalid version string");
  }
  bool in_comments = false;
  for (size_t i = 0; i < version_view.size(); i++) {
    uint8_t b = version_view[i];
    if (b < 32 || b > 126) { // printable ascii range
      return absl::InvalidArgumentError("version string contains invalid characters");
    }
    if (b == ' ') {
      in_comments = true;
    } else if (b == '-' && !in_comments) {
      // '-' is not allowed except in comments
      return absl::InvalidArgumentError("version string contains invalid characters");
    }
  }
  return absl::OkStatus();
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec