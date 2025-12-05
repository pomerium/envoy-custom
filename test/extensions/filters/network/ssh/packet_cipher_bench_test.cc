
#include "source/common/types.h"
#include "source/extensions/filters/network/ssh/packet_cipher.h"
#include "source/extensions/filters/network/ssh/packet_cipher_aead.h"
#include "source/extensions/filters/network/ssh/packet_cipher_etm.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/packet.h"
#include "test/benchmark/main.h"
#include "benchmark/benchmark.h"
#include "test/test_common/test_common.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
namespace test {

static void runBenchmark(::benchmark::State& state, DirectionalPacketCipher& write_cipher, DirectionalPacketCipher& read_cipher) {
  Buffer::OwnedImpl encrypted;
  Buffer::OwnedImpl decrypted;

  wire::ChannelDataMsg msg;
  msg.data = "hello world"_bytes;

  ASSERT_OK(wire::encodePacket(decrypted, msg, write_cipher.blockSize(), write_cipher.aadLen()).status());
  auto packet = decrypted.toString();

  uint32_t seqnum = 0;
  for (auto _ : state) {
    ASSERT_OK(write_cipher.encryptPacket(seqnum, encrypted, decrypted));
    ASSERT_OK(read_cipher.decryptPacket(seqnum, decrypted, encrypted));
    seqnum++;
  }
  EXPECT_EQ(packet, decrypted.toString());
}

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkCipherChacha20Poly1305(::benchmark::State& state) {
  DerivedKeys keys{
    .iv = bytes(),
    .key = randomBytes(64),
    .mac = bytes(),
  };
  DirectionAlgorithms algs{
    .cipher = CipherChacha20Poly1305,
    .mac = "",
    .compression = "",
  };

  DirectionalPacketCipherFactoryRegistry factories;
  factories.registerType<Chacha20Poly1305CipherFactory>();

  auto write_cipher = factories.factoryForName(CipherChacha20Poly1305)->create(keys, algs, openssh::CipherMode::Write);
  auto read_cipher = factories.factoryForName(CipherChacha20Poly1305)->create(keys, algs, openssh::CipherMode::Read);

  runBenchmark(state, *write_cipher, *read_cipher);
}
BENCHMARK(BenchmarkCipherChacha20Poly1305);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkCipherAES128GCM(::benchmark::State& state) {
  DerivedKeys keys{
    .iv = randomBytes(12),
    .key = randomBytes(16),
    .mac = bytes(),
  };
  DirectionAlgorithms algs{
    .cipher = CipherAES128GCM,
    .mac = "",
    .compression = "",
  };

  DirectionalPacketCipherFactoryRegistry factories;
  factories.registerType<AESGCM128CipherFactory>();

  auto write_cipher = factories.factoryForName(CipherAES128GCM)->create(keys, algs, openssh::CipherMode::Write);
  auto read_cipher = factories.factoryForName(CipherAES128GCM)->create(keys, algs, openssh::CipherMode::Read);

  runBenchmark(state, *write_cipher, *read_cipher);
}
BENCHMARK(BenchmarkCipherAES128GCM);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkCipherAES256GCM(::benchmark::State& state) {
  DerivedKeys keys{
    .iv = randomBytes(12),
    .key = randomBytes(32),
    .mac = bytes(),
  };
  DirectionAlgorithms algs{
    .cipher = CipherAES256GCM,
    .mac = "",
    .compression = "",
  };

  DirectionalPacketCipherFactoryRegistry factories;
  factories.registerType<AESGCM256CipherFactory>();

  auto write_cipher = factories.factoryForName(CipherAES256GCM)->create(keys, algs, openssh::CipherMode::Write);
  auto read_cipher = factories.factoryForName(CipherAES256GCM)->create(keys, algs, openssh::CipherMode::Read);

  runBenchmark(state, *write_cipher, *read_cipher);
}
BENCHMARK(BenchmarkCipherAES256GCM);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkCipherAES128CTR(::benchmark::State& state) {
  DerivedKeys keys{
    .iv = randomBytes(16),
    .key = randomBytes(16),
    .mac = randomBytes(32),
  };
  DirectionAlgorithms algs{
    .cipher = CipherAES128CTR,
    .mac = "hmac-sha2-256-etm@openssh.com",
    .compression = "",
  };

  DirectionalPacketCipherFactoryRegistry factories;
  factories.registerType<AES128CTRCipherFactory>();

  auto write_cipher = factories.factoryForName(CipherAES128CTR)->create(keys, algs, openssh::CipherMode::Write);
  auto read_cipher = factories.factoryForName(CipherAES128CTR)->create(keys, algs, openssh::CipherMode::Read);

  runBenchmark(state, *write_cipher, *read_cipher);
}
BENCHMARK(BenchmarkCipherAES128CTR);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkCipherAES192CTR(::benchmark::State& state) {
  DerivedKeys keys{
    .iv = randomBytes(16),
    .key = randomBytes(24),
    .mac = randomBytes(32),
  };
  DirectionAlgorithms algs{
    .cipher = CipherAES192CTR,
    .mac = "hmac-sha2-256-etm@openssh.com",
    .compression = "",
  };

  DirectionalPacketCipherFactoryRegistry factories;
  factories.registerType<AES192CTRCipherFactory>();

  auto write_cipher = factories.factoryForName(CipherAES192CTR)->create(keys, algs, openssh::CipherMode::Write);
  auto read_cipher = factories.factoryForName(CipherAES192CTR)->create(keys, algs, openssh::CipherMode::Read);

  runBenchmark(state, *write_cipher, *read_cipher);
}
BENCHMARK(BenchmarkCipherAES192CTR);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkCipherAES256CTR(::benchmark::State& state) {
  DerivedKeys keys{
    .iv = randomBytes(16),
    .key = randomBytes(32),
    .mac = randomBytes(32),
  };
  DirectionAlgorithms algs{
    .cipher = CipherAES256CTR,
    .mac = "hmac-sha2-256-etm@openssh.com",
    .compression = "",
  };

  DirectionalPacketCipherFactoryRegistry factories;
  factories.registerType<AES256CTRCipherFactory>();

  auto write_cipher = factories.factoryForName(CipherAES256CTR)->create(keys, algs, openssh::CipherMode::Write);
  auto read_cipher = factories.factoryForName(CipherAES256CTR)->create(keys, algs, openssh::CipherMode::Read);

  runBenchmark(state, *write_cipher, *read_cipher);
}
BENCHMARK(BenchmarkCipherAES256CTR);

} // namespace test
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
