#include "source/extensions/request_id/uuidx/config.h"

namespace Envoy::Extensions::RequestId {
constexpr auto pomerium_trace_decision = "x-pomerium-internal-trace-decision";

Tracing::Reason
UUIDxRequestIDExtension::getTraceReason(const Envoy::Http::RequestHeaderMap& request_headers) {
  return getInternalReason(request_headers)
      .value_or(UUIDRequestIDExtension::getTraceReason(request_headers));
}

void UUIDxRequestIDExtension::setTraceReason(Envoy::Http::RequestHeaderMap& request_headers,
                                             Tracing::Reason reason) {
  UUIDRequestIDExtension::setTraceReason(request_headers,
                                         getInternalReason(request_headers).value_or(reason));
}

absl::optional<Tracing::Reason>
UUIDxRequestIDExtension::getInternalReason(const Envoy::Http::RequestHeaderMap& request_headers) {
  static const auto trace_decision_header = Envoy::Http::LowerCaseString(pomerium_trace_decision);
  if (auto&& value = request_headers.get(trace_decision_header); !value.empty()) {
    if (auto&& str = value[0]->value().getStringView(); str.size() == 1) {
      switch (str.at(0)) {
      case '0':
        return Tracing::Reason::NotTraceable;
      case '1':
        return Tracing::Reason::ServiceForced;
      }
    }
  }
  return absl::nullopt;
}

// Factory for the UUID request ID extension.
class UUIDxRequestIDExtensionFactory : public Server::Configuration::RequestIDExtensionFactory {
public:
  std::string name() const override { return "envoy.request_id.uuidx"; }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<UuidxRequestIdConfig>();
  }

  Envoy::Http::RequestIDExtensionSharedPtr
  createExtensionInstance(const Protobuf::Message& config,
                          Server::Configuration::FactoryContext& context) override {
    return std::make_shared<UUIDxRequestIDExtension>(
        dynamic_cast<const UuidxRequestIdConfig&>(config),
        context.serverFactoryContext().api().randomGenerator());
  }
};
REGISTER_FACTORY(UUIDxRequestIDExtensionFactory, Server::Configuration::RequestIDExtensionFactory);

} // namespace Envoy::Extensions::RequestId