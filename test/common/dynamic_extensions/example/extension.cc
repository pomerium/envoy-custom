#include "source/common/dynamic_extensions/extension.h"
#include "envoy/server/instance.h"
#include "source/common/common/logger.h"

DYNAMIC_EXTENSION("example-extension");
DYNAMIC_EXTENSION_LICENSE("Apache-2.0");

DYNAMIC_EXTENSION_EXPORT void dynamicExtensionInit(Envoy::Server::Instance& server) {
  static Envoy::Server::ServerLifecycleNotifier::HandlePtr callback_handle;
  callback_handle = server.lifecycleNotifier().registerCallback(
    Envoy::Server::ServerLifecycleNotifier::Stage::ShutdownExit,
    [](Envoy::Event::PostCb completion_cb) {
      ENVOY_LOG_MISC(info, "[example extension] shutdown hook");
      completion_cb();
    });
  ENVOY_LOG_MISC(info, "[example extension] loaded");
}