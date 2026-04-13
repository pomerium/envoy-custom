#include "source/common/dynamic_extensions/extension.h"
#include "envoy/server/instance.h"
#include "absl/synchronization/notification.h"

DYNAMIC_EXTENSION("test.tls");
DYNAMIC_EXTENSION_LICENSE("Apache-2.0");

class TestThreadLocalData : public Envoy::ThreadLocal::ThreadLocalObject {
public:
  TestThreadLocalData(const std::string& data)
      : data_(data) {}

  std::string data_;
};

static std::unique_ptr<Envoy::ThreadLocal::TypedSlot<TestThreadLocalData>> test_thread_local_slot_;

extern absl::Notification test_wait_tls_init;
extern void writeTestData(const std::string& data);

DYNAMIC_EXTENSION_EXPORT void dynamicExtensionInit(Envoy::Server::Instance& server) {
  test_thread_local_slot_ = Envoy::ThreadLocal::TypedSlot<TestThreadLocalData>::makeUnique(server.threadLocal());

  test_thread_local_slot_->set([](Envoy::Event::Dispatcher& d) {
    return std::make_shared<TestThreadLocalData>(d.name());
  });

  test_thread_local_slot_->runOnAllThreads(
    [](Envoy::OptRef<TestThreadLocalData> data) {
      writeTestData(data->data_);
    },
    [&] {
      test_wait_tls_init.Notify();
    });
}
