#include "source/common/dynamic_extensions/extension.h"
#include "source/common/dynamic_extensions/factory.h"
#include "envoy/server/instance.h"
#include "test/extensions/filters/http/common/empty_http_filter_config.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

DYNAMIC_EXTENSION("test-http-factory");
DYNAMIC_EXTENSION_LICENSE("Apache-2.0");

extern std::atomic<int> test_extension_http_filters_created;
extern std::atomic<int> test_extension_http_filters_destroyed;

class TestExtensionHttpFilter : public Envoy::Http::PassThroughFilter {
public:
  TestExtensionHttpFilter() {
    test_extension_http_filters_created++;
  }
  ~TestExtensionHttpFilter() {
    test_extension_http_filters_destroyed++;
  }
};

class TestExtensionHttpFilterFactory : public Envoy::Extensions::HttpFilters::Common::EmptyHttpDualFilterConfig {
public:
  TestExtensionHttpFilterFactory() : EmptyHttpDualFilterConfig("test.dynamic_extensions.http_filter") {
    ENVOY_LOG_MISC(info, "TestExtensionHttpFilterFactory loaded");
  }
  ~TestExtensionHttpFilterFactory() {
    ENVOY_LOG_MISC(info, "TestExtensionHttpFilterFactory destroyed");
  }

  absl::StatusOr<Envoy::Http::FilterFactoryCb>
  createDualFilter(const std::string&, Envoy::Server::Configuration::ServerFactoryContext&) override {
    return [](Envoy::Http::FilterChainFactoryCallbacks& callbacks) -> void {
      callbacks.addStreamFilter(std::make_shared<TestExtensionHttpFilter>());
    };
  }
};

DYNAMIC_EXTENSION_USE_FACTORY_BASE(Envoy::Server::Configuration::NamedHttpFilterConfigFactory);

DYNAMIC_EXTENSION_EXPORT void dynamicExtensionInit(Envoy::Server::Instance& server) {
  DYNAMIC_EXTENSION_REGISTER_FACTORY(TestExtensionHttpFilterFactory, Envoy::Server::Configuration::NamedHttpFilterConfigFactory);
}