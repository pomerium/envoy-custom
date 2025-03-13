#pragma once

#pragma clang unsafe_buffer_usage begin
#include "envoy/server/factory_context.h"
#include "api/extensions/filters/network/ssh/filters/session_recording/session_recording.pb.h"
#pragma clang unsafe_buffer_usage end

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {
using pomerium::extensions::ssh::filters::session_recording::Config;

struct RecordingEntryInfo {
  std::string name;
  std::string path;
  uint64_t size_bytes;
  Envoy::SystemTime created_at;

  friend auto operator<=>(const RecordingEntryInfo& lhs, const RecordingEntryInfo& rhs) {
    return lhs.created_at <=> rhs.created_at;
  }
};

class AdminApi : public Logger::Loggable<Logger::Id::filter> {
public:
  AdminApi(std::shared_ptr<Config> config, Server::Configuration::FactoryContext& ctx);
  Http::Code handleListEndpoint(Http::ResponseHeaderMap& response_headers,
                                Buffer::Instance& response,
                                Server::AdminStream&);
  Http::Code handleGetEndpoint(Http::ResponseHeaderMap& response_headers,
                               Buffer::Instance& response,
                               Server::AdminStream&);
  Http::Code handleViewerEndpoint(Http::ResponseHeaderMap& response_headers,
                                  Buffer::Instance& response,
                                  Server::AdminStream&);

private:
  void refreshAccessLogs();
  Api::Api& api_;
  std::shared_ptr<Config> config_;
  Filesystem::WatcherPtr watcher_;
  std::unordered_map<std::string, RecordingEntryInfo> entries_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording