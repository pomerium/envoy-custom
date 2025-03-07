#pragma once

#include <memory>

#include "envoy/thread_local/thread_local.h"

#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/frame.h"
#include "source/extensions/filters/network/ssh/transport.h"
#include "source/extensions/filters/network/ssh/shared.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {
using ::Envoy::Event::Dispatcher;

class SessionMultiplexer : public SourceCallbacks,
                           public MirrorCallbacks,
                           public std::enable_shared_from_this<SessionMultiplexer>,
                           public Logger::Loggable<Logger::Id::filter> {
public:
  explicit SessionMultiplexer(
    Api::Api& api,
    std::shared_ptr<ThreadLocal::TypedSlot<SharedThreadLocalData>> tls,
    Dispatcher& dispatcher);

  void onStreamBegin(const AuthState& auth_state);

  void onStreamEnd();

  void onEnd() override;

  void handleDownstreamToUpstreamMessage(wire::Message& msg);
  void handleUpstreamToDownstreamMessage(wire::Message& msg);

private:
  void onMsg(const wire::Message& msg) override;
  void inject(const wire::ChannelDataMsg& msg) override;

  void onMirrorAdded(std::shared_ptr<MirrorCallbacks> mc) override;
  void onMirrorRemoved(std::shared_ptr<MirrorCallbacks> mc) override;

  void updateSource(const wire::ChannelDataMsg& msg);
  void resizeSource(const wire::ChannelRequestMsg& msg);

  Api::Api& api_;
  std::optional<uint64_t> current_stream_id_;
  bool stream_ending_{false};
  std::optional<uint32_t> sender_channel_;
  std::shared_ptr<SourceInterface> source_interface_;

  std::shared_ptr<ThreadLocal::TypedSlot<SharedThreadLocalData>> tls_;
  Dispatcher& local_dispatcher_;
  Codec::MultiplexingInfo info_;
  std::vector<wire::Message> log_;
  std::unordered_set<std::shared_ptr<MirrorCallbacks>> active_mirrors_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec