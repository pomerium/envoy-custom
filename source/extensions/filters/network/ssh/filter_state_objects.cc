#include "source/extensions/filters/network/ssh/filter_state_objects.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/registry/registry.h"
#include "source/common/network/utility.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

const std::string& DownstreamSourceAddress::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "pomerium.extensions.ssh.downstream_source_address");
}

std::optional<std::string> DownstreamSourceAddress::serializeAsString() const {
  auto addr = getAddress();
  if (addr == nullptr) {
    return std::nullopt;
  }
  return addr->asString();
}

const std::string& DownstreamSourceAddressFilterStateFactory::key() {
  return DownstreamSourceAddress::key();
}

std::unique_ptr<StreamInfo::FilterState::Object>
DownstreamSourceAddressFilterStateFactory::createFromBytes(absl::string_view data) const {
  const auto address = Network::Utility::parseInternetAddressAndPortNoThrow(std::string(data));
  if (address == nullptr) {
    return nullptr;
  }
  return std::make_unique<DownstreamSourceAddress>(address);
}

std::string DownstreamSourceAddressFilterStateFactory::name() const {
  return key();
}

REGISTER_FACTORY(DownstreamSourceAddressFilterStateFactory, StreamInfo::FilterState::ObjectFactory);

const std::string& RequestedServerName::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "pomerium.extensions.ssh.requested_server_name");
}

const std::string& RequestedServerNameFilterStateFactory::key() {
  return RequestedServerName::key();
}

std::string RequestedServerNameFilterStateFactory::name() const {
  return key();
}

REGISTER_FACTORY(RequestedServerNameFilterStateFactory, StreamInfo::FilterState::ObjectFactory);

const std::string& RequestedPath::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "pomerium.extensions.ssh.requested_path");
}

const std::string& RequestedPathFilterStateFactory::key() {
  return RequestedPath::key();
}

std::string RequestedPathFilterStateFactory::name() const {
  return key();
}

REGISTER_FACTORY(RequestedPathFilterStateFactory, StreamInfo::FilterState::ObjectFactory);

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec