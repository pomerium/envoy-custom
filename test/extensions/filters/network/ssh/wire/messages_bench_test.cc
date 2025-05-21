
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/util.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"
#include "test/benchmark/main.h"
#include "benchmark/benchmark.h"

namespace wire::test {

static wire::KexInitMsg init_msg = [] {
  wire::KexInitMsg m;
  populateFields(m);
  return m;
}();

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkMessageMove(benchmark::State& state) {
  Message m1{init_msg};
  Message m2;
  bool b{false};
  for (auto _ : state) {
    if (!b) {
      m2 = std::move(m1);
    } else {
      m1 = std::move(m2);
    }
    b = !b;
  }
}
BENCHMARK(BenchmarkMessageMove);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkMessageCopy(benchmark::State& state) {
  Message m1{init_msg};
  for (auto _ : state) {
    benchmark::DoNotOptimize(auto(m1));
  }
}
BENCHMARK(BenchmarkMessageCopy);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkMessagePtrMove(benchmark::State& state) {
  MessagePtr m1 = std::make_unique<Message>(init_msg);
  MessagePtr m2;
  bool b{false};
  for (auto _ : state) {
    if (!b) {
      m2 = std::move(m1);
    } else {
      m1 = std::move(m2);
    }
    b = !b;
  }
}
BENCHMARK(BenchmarkMessagePtrMove);

} // namespace wire::test