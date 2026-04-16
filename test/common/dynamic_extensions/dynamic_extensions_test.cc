#include "api/extensions/bootstrap/dynamic_extension_loader/dynamic_extension_loader.pb.h"
#include "test/integration/base_integration_test.h"
#include "test/test_common/status_utility.h"
#include "gtest/gtest.h"
#include <csignal>
#include <sstream>
#include <unistd.h>
#include <utility>

using namespace std::literals;

#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#define SANITIZER_ENABLED
#endif

// NOLINTBEGIN(readability-identifier-naming)

class DynamicExtensionsIntegrationTest : public testing::Test,
                                         public Envoy::BaseIntegrationTest {
public:
  DynamicExtensionsIntegrationTest()
      : Envoy::BaseIntegrationTest(Envoy::Network::Address::IpVersion::v4) {
  }

  void initialize() override {
    Envoy::BaseIntegrationTest::initialize();
    registerTestServerPorts({}); // register the admin port
  }

  struct exec_result {
    int exit_code;
    std::string out;
  };

  void ConfigureExtensionLoader(std::vector<std::string> extension_paths,
                                std::unordered_map<std::string, const Envoy::Protobuf::Message&> configs = {}) {
    config_helper_.addConfigModifier([=](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      if (!bootstrap.bootstrap_extensions().empty()) {
        PANIC("test bug: ConfigureExtensionLoader called twice");
      }
      auto* ext = bootstrap.add_bootstrap_extensions();
      ext->set_name("envoy.bootstrap.dynamic_extension_loader");
      pomerium::extensions::dynamic_extension_loader::Config config;
      for (const auto& path : extension_paths) {
        config.add_paths(path);
      }
      for (const auto& [id, msg] : configs) {
        (*config.mutable_extension_configs())[id].PackFrom(msg);
      }
      ext->mutable_typed_config()->PackFrom(config);
    });
  }

  std::string SelfPath() {
    std::string buf(1024, 0);
    auto n = readlink("/proc/self/exe", buf.data(), buf.size());
    if (n == -1) {
      PANIC("readlink failed");
    }
    buf.resize(n);
    return buf;
  }

  absl::StatusOr<Envoy::Json::ObjectSharedPtr> FetchAdminApiStatus() {
    auto response = Envoy::IntegrationUtil::makeSingleRequest(
      lookupPort("admin"), "GET", "/dynamic_extensions/status",
      "", Envoy::Http::CodecType::HTTP1, version_);

    if (!response->complete()) {
      return absl::InternalError("admin api request failed");
    }
    return Envoy::Json::Factory::loadFromString(response->body());
  }

  absl::StatusOr<exec_result> RunReadExtension(std::vector<std::string> args) {
    int stdout_pipe[2];
    if (pipe(static_cast<int*>(stdout_pipe)) != 0) {
      return absl::InternalError("pipe() failed");
    }
    auto path = Envoy::TestEnvironment::runfilesPath("tools/read-extension", "pomerium_envoy");
    std::vector<char*> argv;
    argv.push_back(path.data());
    for (std::string& arg : args) {
      argv.push_back(arg.data());
    }
    argv.push_back(nullptr);
    auto pid = fork();
    if (pid == -1) {
      return absl::InternalError("fork() failed");
    }
    if (pid == 0) {
      close(stdout_pipe[0]);
      dup2(stdout_pipe[1], fileno(stdout));
      dup2(stdout_pipe[1], fileno(stderr));
      close(stdout_pipe[1]);

      execve(path.c_str(), std::as_const(argv).data(), environ);
      std::unreachable();
    } else {
      close(stdout_pipe[1]);
      std::stringstream ss;
      std::thread read_thread{[&] {
        std::array<char, 256> buf;
        while (true) {
          ssize_t n = read(stdout_pipe[0], buf.data(), sizeof(buf));
          if (n == -1) {
            PANIC("read() failed");
          }
          ss.write(buf.data(), n);
          if (n == 0) {
            break;
          }
        }
        close(stdout_pipe[0]);
      }};
      int status{};
      while (true) {
        auto w = waitpid(pid, &status, 0);
        if (w == -1) {
          return absl::InternalError("waitpid() failed");
        }
        if (WIFEXITED(status)) {
          read_thread.join();
          return exec_result{
            .exit_code = WEXITSTATUS(status),
            .out = ss.str(),
          };
        } else if (WIFSIGNALED(status)) {
          read_thread.join();
          return absl::InternalError(fmt::format("process killed by signal {}", WTERMSIG(status)));
        }
      }
    }
  }

  AssertionResult CheckExtensionLoaded(Envoy::Json::ObjectSharedPtr status, std::string id) {
    auto obj = status->getObjectArray("loaded");
    if (!obj.ok()) {
      return AssertionFailure() << obj.status();
    }
    for (const auto& entry : *obj) {
      if (*entry->getString("id") == id) {
        return AssertionSuccess();
      }
    }
    return AssertionFailure() << "extension was not reported as loaded by the admin api";
  }

  AssertionResult CheckExtensionFailed(Envoy::Json::ObjectSharedPtr status, std::string id,
                                       std::string kind, std::optional<std::string> error_substring = {}) {
    auto obj = status->getObjectArray("failed");
    if (!obj.ok()) {
      return AssertionFailure() << obj.status();
    }
    for (const auto& entry : *obj) {
      auto info = entry->getObject("info");
      if (!info.ok()) {
        return AssertionFailure() << info.status();
      }
      if (*info->get()->getString("id") == id) {
        if (auto actual = *entry->getString("kind"); actual != kind) {
          return AssertionFailure() << fmt::format("expected failure kind: '{}', actual: '{}'", kind, actual);
        }
        if (error_substring.has_value()) {
          auto actual = *entry->getString("error");
          if (!actual.contains(*error_substring)) {
            return AssertionFailure() << fmt::format(
                     "error message:\n  {}\ndoes not contain expected substring:\n  {}", actual, *error_substring);
          }
        }
        return AssertionSuccess();
      }
    }
    return AssertionFailure() << "extension was not reported as failed by the admin api";
  }
};
// NOLINTEND(readability-identifier-naming)

int test_no_config_dynamic_extension_init_called{};

class NoConfigTest : public DynamicExtensionsIntegrationTest {
public:
  using DynamicExtensionsIntegrationTest::DynamicExtensionsIntegrationTest;

  void SetUp() override {
    test_no_config_dynamic_extension_init_called = 0;

    extension_path_ = Envoy::TestEnvironment::runfilesPath(
      "test/common/dynamic_extensions/test/libtest_no_config.so", "pomerium_envoy");

#ifndef SANITIZER_ENABLED
    auto result = RunReadExtension({"--check", SelfPath(), extension_path_});
    ASSERT_OK(result.status());
    ASSERT_EQ(result->exit_code, 0) << result->out;
#endif
  }

  std::string extension_path_;
};

TEST_F(NoConfigTest, TestNoConfig) {
  ConfigureExtensionLoader({extension_path_});

  ASSERT_EQ(test_no_config_dynamic_extension_init_called, 0);
  initialize();
  ASSERT_EQ(test_no_config_dynamic_extension_init_called, 1);

  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionLoaded(*status, "test.no-config"));
}

TEST_F(NoConfigTest, TestNoConfig_ConfigSet) {
  Envoy::Protobuf::StringValue str;
  str.set_value("foo");
  ConfigureExtensionLoader({extension_path_}, {{"test.no-config", str}});

  ASSERT_EQ(test_no_config_dynamic_extension_init_called, 0);
  initialize();
  ASSERT_EQ(test_no_config_dynamic_extension_init_called, 0);

  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionFailed(*status, "test.no-config", "initialization_failure"));
}

int test_optional_config_dynamic_extension_init_called{};

class OptionalConfigTest : public DynamicExtensionsIntegrationTest {
public:
  using DynamicExtensionsIntegrationTest::DynamicExtensionsIntegrationTest;

  void SetUp() override {
    test_optional_config_dynamic_extension_init_called = 0;

    extension_path_ = Envoy::TestEnvironment::runfilesPath(
      "test/common/dynamic_extensions/test/libtest_optional_config.so", "pomerium_envoy");

#ifndef SANITIZER_ENABLED
    auto result = RunReadExtension({"--check", SelfPath(), extension_path_});
    ASSERT_OK(result.status());
    ASSERT_EQ(result->exit_code, 0) << result->out;
#endif
  }

  std::string extension_path_;
};

TEST_F(OptionalConfigTest, TestOptionalConfig_ConfigNotSet) {
  ConfigureExtensionLoader({extension_path_});

  ASSERT_EQ(test_optional_config_dynamic_extension_init_called, 0);
  initialize();
  ASSERT_EQ(test_optional_config_dynamic_extension_init_called, 1);

  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionLoaded(*status, "test.optional-config"));
}

TEST_F(OptionalConfigTest, TestOptionalConfig_ConfigSet) {
  Envoy::Protobuf::StringValue str;
  str.set_value("foo");
  ConfigureExtensionLoader({extension_path_}, {{"test.optional-config", str}});

  ASSERT_EQ(test_optional_config_dynamic_extension_init_called, 0);
  initialize();
  ASSERT_EQ(test_optional_config_dynamic_extension_init_called, 2);

  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionLoaded(*status, "test.optional-config"));
}

int test_required_config_dynamic_extension_init_called{};

class RequiredConfigTest : public DynamicExtensionsIntegrationTest {
public:
  using DynamicExtensionsIntegrationTest::DynamicExtensionsIntegrationTest;

  void SetUp() override {
    test_required_config_dynamic_extension_init_called = 0;

    extension_path_ = Envoy::TestEnvironment::runfilesPath(
      "test/common/dynamic_extensions/test/libtest_required_config.so", "pomerium_envoy");

#ifndef SANITIZER_ENABLED
    auto result = RunReadExtension({"--check", SelfPath(), extension_path_});
    ASSERT_OK(result.status());
    ASSERT_EQ(result->exit_code, 0) << result->out;
#endif
  }

  std::string extension_path_;
};

TEST_F(RequiredConfigTest, TestRequiredConfig_ConfigNotSet) {
  ConfigureExtensionLoader({extension_path_});

  ASSERT_EQ(test_required_config_dynamic_extension_init_called, 0);
  initialize();
  ASSERT_EQ(test_required_config_dynamic_extension_init_called, 0);

  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionFailed(*status, "test.required-config", "initialization_failure"));
}

TEST_F(RequiredConfigTest, TestRequiredConfig_ConfigSet) {
  Envoy::Protobuf::StringValue str;
  str.set_value("foo");
  ConfigureExtensionLoader({extension_path_}, {{"test.required-config", str}});

  ASSERT_EQ(test_required_config_dynamic_extension_init_called, 0);
  initialize();
  ASSERT_EQ(test_required_config_dynamic_extension_init_called, 2);

  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionLoaded(*status, "test.required-config"));
}

class NoInitTest : public DynamicExtensionsIntegrationTest {
public:
  using DynamicExtensionsIntegrationTest::DynamicExtensionsIntegrationTest;

  void SetUp() override {
    extension_path_ = Envoy::TestEnvironment::runfilesPath(
      "test/common/dynamic_extensions/test/libtest_no_init.so", "pomerium_envoy");

#ifndef SANITIZER_ENABLED
    auto result = RunReadExtension({"--check", SelfPath(), extension_path_});
    ASSERT_OK(result.status());
    ASSERT_EQ(result->exit_code, 0) << result->out;
#endif
  }

  std::string extension_path_;
};

TEST_F(NoInitTest, TestNoInit_ConfigNotSet) {
  ConfigureExtensionLoader({extension_path_});

  initialize();

  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionLoaded(*status, "test.no-init"));
}

TEST_F(NoInitTest, TestNonit_ConfigSet) {
  Envoy::Protobuf::StringValue str;
  str.set_value("foo");
  ConfigureExtensionLoader({extension_path_}, {{"test.no-init", str}});

  initialize();

  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionFailed(*status, "test.no-init", "initialization_failure"));
}

class MissingWeakDependencyTest : public DynamicExtensionsIntegrationTest {
public:
  using DynamicExtensionsIntegrationTest::DynamicExtensionsIntegrationTest;

  void SetUp() override {
    extension_path_ = Envoy::TestEnvironment::runfilesPath(
      "test/common/dynamic_extensions/test/libtest_missing_symbol.so", "pomerium_envoy");

#ifndef SANITIZER_ENABLED
    auto result = RunReadExtension({"--check", SelfPath(), "--demangle", extension_path_});
    ASSERT_OK(result.status());
    EXPECT_NE(result->exit_code, 0);
    ASSERT_THAT(result->out, testing::HasSubstr("missing symbol required by extension: symbolNotAvailableInExtensionHost()"));
#endif
  }

  std::string extension_path_;
};

TEST_F(MissingWeakDependencyTest, TestMissingWeakDependency) {
  ConfigureExtensionLoader({extension_path_});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionFailed(*status, "test.missing-symbol", "load_failure"));
}

TEST_F(DynamicExtensionsIntegrationTest, TestVersionMismatch) {
  auto extension_path = Envoy::TestEnvironment::runfilesPath(
    "test/common/dynamic_extensions/test/libtest_version_mismatch.so", "pomerium_envoy");

  ConfigureExtensionLoader({extension_path});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionFailed(*status, "test.version-mismatch", "load_failure",
                                   "extension was built for version 0000000000000000000000000000000000000000, but the current version is"));
}

TEST_F(DynamicExtensionsIntegrationTest, TestMetadataUnknownKeys) {
  auto extension_path = Envoy::TestEnvironment::runfilesPath(
    "test/common/dynamic_extensions/test/libtest_md_unknown_keys.so", "pomerium_envoy");

  ConfigureExtensionLoader({extension_path});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionLoaded(*status, "test.md-unknown-keys"));

  auto obj = (*status)->getObjectArray("loaded");
  for (const auto& entry : *obj) {
    if (*entry->getString("id") == "test.md-unknown-keys") {
      auto md = entry->getObject("unknown_keys");
      EXPECT_EQ("bar"s, *md->get()->getString("foo"));
      EXPECT_EQ("baz"s, *md->get()->getString("bar"));
    }
  }
}

class ThreadLocalStorageTest : public DynamicExtensionsIntegrationTest {
public:
  ThreadLocalStorageTest() {
    concurrency_ = 4;
  }

  void SetUp() override {
    extension_path_ = Envoy::TestEnvironment::runfilesPath(
      "test/common/dynamic_extensions/test/libtest_tls.so", "pomerium_envoy");

#ifndef SANITIZER_ENABLED
    auto result = RunReadExtension({"--check", SelfPath(), extension_path_});
    ASSERT_OK(result.status());
    ASSERT_EQ(result->exit_code, 0) << result->out;
#endif
  }

  std::string extension_path_;
};

static absl::Mutex mu;
static std::vector<std::string> test_data ABSL_GUARDED_BY(mu);

absl::Notification test_wait_tls_init;
void writeTestData(const std::string& data) {
  absl::MutexLock lock(mu);
  test_data.push_back(data);
}

TEST_F(ThreadLocalStorageTest, TestTLS) {
  ConfigureExtensionLoader({extension_path_});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionLoaded(*status, "test.tls"));

  ASSERT_TRUE(test_wait_tls_init.WaitForNotificationWithTimeout(absl::Seconds(1)));

  absl::MutexLock lock(mu);
  std::sort(test_data.begin(), test_data.end());
  auto expected = std::vector<std::string>{{"main_thread", "worker_0", "worker_1", "worker_2", "worker_3"}};
  EXPECT_EQ(expected, test_data);
}

std::atomic<int> test_extension_http_filters_created;
std::atomic<int> test_extension_http_filters_destroyed;

class FactoryRegistrationTest : public DynamicExtensionsIntegrationTest {
public:
  FactoryRegistrationTest() {
    test_extension_http_filters_created = 0;
    test_extension_http_filters_destroyed = 0;
    autonomous_allow_incomplete_streams_ = true;
    autonomous_upstream_ = true;

    // from Envoy::HttpIntegrationTest::HttpIntegrationTest
    config_helper_.renameListener("http");
    config_helper_.addRuntimeOverride("envoy.reloadable_features.no_extension_lookup_by_name",
                                      "false");
  }
  void SetUp() override {
    extension_path_ = Envoy::TestEnvironment::runfilesPath(
      "test/common/dynamic_extensions/test/libtest_http_factory.so", "pomerium_envoy");
  }
  std::string extension_path_;
};

TEST_F(FactoryRegistrationTest, TestExtensionRegistersHttpFilterFactory) {
  ConfigureExtensionLoader({extension_path_});
  config_helper_.prependFilter("{ name: test.dynamic_extensions.http_filter }");
  initialize();

  auto response = Envoy::IntegrationUtil::makeSingleRequest(
    lookupPort("http"), "GET", "/",
    "", Envoy::Http::CodecType::HTTP1, version_);
  ASSERT_TRUE(response->complete());
  ASSERT_EQ("200", response->headers().getStatusValue());

  ASSERT_EQ(test_extension_http_filters_created.load(), 1);
  ASSERT_EQ(test_extension_http_filters_destroyed.load(), 1);
}

TEST_F(DynamicExtensionsIntegrationTest, TestAdminApiMethodNotAllowed) {
  ConfigureExtensionLoader({});

  initialize();

  auto response = Envoy::IntegrationUtil::makeSingleRequest(
    lookupPort("admin"), "POST", "/dynamic_extensions/status",
    "", Envoy::Http::CodecType::HTTP1, version_);
  ASSERT_TRUE(response->complete());
  ASSERT_EQ("405", response->headers().getStatusValue());
}

TEST_F(DynamicExtensionsIntegrationTest, TestLoadDuplicatePaths) {
  auto extension_path = Envoy::TestEnvironment::runfilesPath(
    "test/common/dynamic_extensions/test/libtest_no_config.so", "pomerium_envoy");
  ConfigureExtensionLoader({extension_path, extension_path, extension_path});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionLoaded(*status, "test.no-config"));

  ASSERT_EQ(1, status->get()->getObjectArray("loaded")->size());
}

TEST_F(DynamicExtensionsIntegrationTest, TestLoadDuplicateIds) {
  auto path1 = Envoy::TestEnvironment::runfilesPath(
    "test/common/dynamic_extensions/test/libtest_no_config.so", "pomerium_envoy");
  auto path2 = Envoy::TestEnvironment::runfilesPath(
    "test/common/dynamic_extensions/test/libtest_no_config_2.so", "pomerium_envoy");

  ConfigureExtensionLoader({path1, path2});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);
  ASSERT_TRUE(CheckExtensionLoaded(*status, "test.no-config"));

  // duplicates are ignored
  ASSERT_EQ(1, status->get()->getObjectArray("loaded")->size());
  ASSERT_EQ(0, status->get()->getObjectArray("failed")->size());
}

TEST_F(DynamicExtensionsIntegrationTest, TestNoMetadata) {
  auto extension_path = Envoy::TestEnvironment::runfilesPath(
    "test/common/dynamic_extensions/test/libtest_no_metadata.so", "pomerium_envoy");

  ConfigureExtensionLoader({extension_path});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);

  ASSERT_EQ(0, status->get()->getObjectArray("loaded")->size());
  ASSERT_EQ(0, status->get()->getObjectArray("failed")->size());
}

TEST_F(DynamicExtensionsIntegrationTest, TestNoID) {
  auto extension_path = Envoy::TestEnvironment::runfilesPath(
    "test/common/dynamic_extensions/test/libtest_no_id.so", "pomerium_envoy");

  ConfigureExtensionLoader({extension_path});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);

  ASSERT_EQ(0, status->get()->getObjectArray("loaded")->size());
  ASSERT_EQ(0, status->get()->getObjectArray("failed")->size());
}

TEST_F(DynamicExtensionsIntegrationTest, TestInvalidID) {
  auto extension_path = Envoy::TestEnvironment::runfilesPath(
    "test/common/dynamic_extensions/test/libtest_invalid_id.so", "pomerium_envoy");

  ConfigureExtensionLoader({extension_path});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);

  ASSERT_EQ(0, status->get()->getObjectArray("loaded")->size());
  ASSERT_EQ(0, status->get()->getObjectArray("failed")->size());
}

TEST_F(DynamicExtensionsIntegrationTest, TestFileNotFound) {
  auto extension_path = Envoy::TestEnvironment::runfilesPath(
    "test/common/dynamic_extensions/test/nonexistent.so", "pomerium_envoy");

  ConfigureExtensionLoader({extension_path});

  initialize();
  auto status = FetchAdminApiStatus();
  ASSERT_OK(status);

  ASSERT_EQ(0, status->get()->getObjectArray("loaded")->size());
  ASSERT_EQ(0, status->get()->getObjectArray("failed")->size());
}
