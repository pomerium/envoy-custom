#include "test/extensions/filters/network/ssh/test_env_util.h"
#include "test/test_common/test_common.h"
#include "test/test_common/environment.h"
#include "test/test_common/file_system_for_test.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

std::string copyTestdataToWritableTmp(const std::string& path, mode_t mode) {
  const std::string runfilePath = Envoy::TestEnvironment::runfilesPath(path, "openssh_portable");
  auto data = Envoy::TestEnvironment::readFileToStringForTest(runfilePath);
  auto outPath = Envoy::TestEnvironment::temporaryPath(path);
  auto outPathSplit = Envoy::Filesystem::fileSystemForTest().splitPathFromFilename(outPath);
  EXPECT_OK(outPathSplit.status());
  Envoy::TestEnvironment::createPath(std::string(outPathSplit->directory_));
  Envoy::TestEnvironment::writeStringToFileForTest(outPath, data, true, true);
  EXPECT_EQ(0, chmod(outPath.c_str(), mode));
  return outPath;
}

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec