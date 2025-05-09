
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/wire/util.h"
#include "test/benchmark/main.h"
#include "benchmark/benchmark.h"
#include "test/extensions/filters/network/ssh/wire/test_field_reflect.h"

namespace wire::test {

static const wire::KexInitMsg init_msg = [] {
  wire::KexInitMsg m;
  populateFields(m);
  return m;
}();
static const bytes init_msg_bytes = *encodeTo<bytes>(init_msg);

class TestBufferFragment : public Envoy::Buffer::BufferFragment {
public:
  TestBufferFragment(size_t size)
      : bytes_(size) {}

  const void* data() const override { return bytes_.data(); }
  size_t size() const override { return bytes_.size(); }
  void done() override {};

private:
  bytes bytes_;
};

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkEncodeKexInitMsg(benchmark::State& state) {
  TestBufferFragment fragment(init_msg_bytes.size());
  for (auto _ : state) {
    Envoy::Buffer::OwnedImpl buffer;
    buffer.addBufferFragment(fragment);
    init_msg.encode(buffer).IgnoreError();
  }
}
BENCHMARK(BenchmarkEncodeKexInitMsg);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BenchmarkDecodeKexInitMsg(benchmark::State& state) {
  for (auto _ : state) {
    KexInitMsg out;
    with_buffer_view(init_msg_bytes, [&out](Envoy::Buffer::Instance& buffer) {
      out.decode(buffer, buffer.length()).IgnoreError();
    });
  }
}
BENCHMARK(BenchmarkDecodeKexInitMsg);

} // namespace wire::test