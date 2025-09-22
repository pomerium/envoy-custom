#include "source/extensions/filters/network/ssh/filter_state_objects.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/registry/registry.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

const std::string& DownstreamSourceAddressFilterStateFactory::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "pomerium.extensions.ssh.downstream_source_address");
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

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec