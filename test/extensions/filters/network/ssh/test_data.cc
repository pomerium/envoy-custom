#include "test/extensions/filters/network/ssh/test_data.h"

#include "test/mocks/api/mocks.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

void setupMockFilesystem(NiceMock<Api::MockApi>& api, NiceMock<Filesystem::MockInstance>& file_system) {
  EXPECT_CALL(api, fileSystem()).WillRepeatedly(ReturnRef(file_system));

  EXPECT_CALL(file_system, fileReadToEnd(_))
    .WillRepeatedly([](const std::string& filename) {
      return absl::StatusOr<std::string>{test_file_contents.at(filename)};
    });
}
} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec