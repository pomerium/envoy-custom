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

static Envoy::ThreadLocal::TypedSlotPtr<TestThreadLocalData> test_thread_local_slot_;
static Envoy::Server::ServerLifecycleNotifier::HandlePtr test_shutdown_callback_handle_;

extern absl::Notification test_wait_tls_init;
extern void writeTestData(const std::string& data);

DYNAMIC_EXTENSION_EXPORT void dynamicExtensionInit(Envoy::Server::Instance& server) {
  std::atexit(+[] {
    RELEASE_ASSERT(test_thread_local_slot_ == nullptr, "bug: test_thread_local_slot_ was not deleted before exit");
    RELEASE_ASSERT(test_shutdown_callback_handle_ == nullptr, "bug: test_shutdown_callback_handle_ was not deleted before exit");
  });

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

  // The slot must be deleted manually here; static destructors are called at program exit, so it
  // would outlive the server otherwise. (this is specific to this test, thread local slots are
  // normally not declared as static globals)
  // Note: this is only relevant because extensions have RTLD_NODELETE enabled. If the extension
  // were really unloaded on dlclose() (called from ~DynamicExtensionHandle()) the slot would be
  // destroyed when the extension loader instance is destroyed. From here, there isn't a good place
  // to store data that is "global" but scoped to the lifetime of the server instance, but doing so
  // should not be required outside of tests.
  test_shutdown_callback_handle_ = server.lifecycleNotifier().registerCallback(
    Envoy::Server::ServerLifecycleNotifier::Stage::ShutdownExit,
    []() {
      test_thread_local_slot_.reset();
      // also delete the handle itself, as it too would outlive the server instance
      // (deleting the handle inside the callback is allowed)
      test_shutdown_callback_handle_.reset();
    });
}
