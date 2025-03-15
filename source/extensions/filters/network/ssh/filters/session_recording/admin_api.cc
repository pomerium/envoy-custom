#include "source/extensions/filters/network/ssh/filters/session_recording/admin_api.h"
#include "source/extensions/filters/network/ssh/filters/session_recording/web/assets.h"

#include "absl/strings/str_replace.h"
#include "source/common/filesystem/directory.h"
#include "source/common/json/json_streamer.h"

#include <algorithm>

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {
using namespace std::literals;

static const std::string index_html = absl::StrReplaceAll(
  Web::embedded_index_html,
  {{"/*%asciinema_player.css%*/", Web::embedded_asciinema_player_css},
   {"/*%asciinema_player.min.js%*/", Web::embedded_asciinema_player_js}});

AdminApi::AdminApi(std::shared_ptr<Config> config, Server::Configuration::FactoryContext& ctx)
    : api_(ctx.serverFactoryContext().api()), config_(config) {
  ctx.serverFactoryContext().admin()->addHandler(
    "/session_recordings/list",
    "List session recordings",
    MAKE_ADMIN_HANDLER(handleListEndpoint),
    false,
    false);
  ctx.serverFactoryContext().admin()->addHandler(
    "/session_recordings/get",
    "Download session recording",
    MAKE_ADMIN_HANDLER(handleGetEndpoint),
    false,
    false);
  ctx.serverFactoryContext().admin()->addHandler(
    "/session_recordings/viewer",
    "Session recording viewer",
    MAKE_ADMIN_HANDLER(handleViewerEndpoint),
    false,
    false);

  refreshAccessLogs();
}
Http::Code AdminApi::handleListEndpoint(Http::ResponseHeaderMap& response_headers,
                                        Buffer::Instance& response,
                                        Server::AdminStream& stream) {
  if (stream.getRequestHeaders().getMethodValue() != "GET") {
    return Http::Code::MethodNotAllowed;
  }
  refreshAccessLogs();

  response_headers.setReferenceContentType("application/json");
  Json::BufferStreamer w(response);
  auto arr = w.makeRootArray();
  std::vector<RecordingEntryInfo> values;
  for (const auto& [_, entry] : entries_) {
    values.push_back(entry);
  }
  std::sort(values.begin(), values.end(), std::greater{});

  for (const auto& entry : values) {
    auto obj = arr->addMap();
    obj->addKey("name");
    obj->addString(entry.name);
    obj->addKey("size");
    obj->addNumber(entry.size_bytes);
    obj->addKey("created_at");
    obj->addString(absl::FormatTime(absl::FromChrono(entry.created_at)));
  }
  return Http::Code::OK;
}

Http::Code AdminApi::handleGetEndpoint(Http::ResponseHeaderMap& response_headers,
                                       Buffer::Instance& response,
                                       Server::AdminStream& stream) {
  refreshAccessLogs();
  auto params = stream.queryParams();
  auto recName = params.getFirstValue("recording_name");
  if (!recName.has_value()) {
    response.add("missing required query parameter: 'recording_name'");
    return Http::Code::BadRequest;
  }
  if (!entries_.contains(*recName)) {
    return Http::Code::NotFound;
  }

  auto data = api_.fileSystem().fileReadToEnd(entries_[*recName].path);
  if (!data.ok()) {
    response.add("error reading file: ");
    response.add(data.status().message());
    return Http::Code::InternalServerError;
  }
  response_headers.setContentType("application/x-asciicast");
  response_headers.setCopy(Http::LowerCaseString("content-disposition"), fmt::format("attachment; filename=\"{}\"", *recName));
  response_headers.setContentLength(data->size());
  response.add(*data);
  return Http::Code::OK;
}

Http::Code AdminApi::handleViewerEndpoint(Http::ResponseHeaderMap& response_headers,
                                          Buffer::Instance& response,
                                          Server::AdminStream& stream) {
  auto params = stream.queryParams();
  auto recName = params.getFirstValue("recording_name");
  if (!recName.has_value()) {
    response.add("missing required query parameter: 'recording_name'");
    return Http::Code::BadRequest;
  }
  if (!entries_.contains(*recName)) {
    return Http::Code::NotFound;
  }

  response_headers.setContentType("text/html");
  response.add(index_html);
  return Http::Code::OK;
}

void AdminApi::refreshAccessLogs() {
  auto dir = config_->storage_dir();
  if (api_.fileSystem().illegalPath(dir)) {
    ENVOY_LOG(error, "illegal path for access_log_storage_dir: {}", dir);
    return;
  }
  Filesystem::Directory it(dir);

  std::unordered_map<std::string, RecordingEntryInfo> files;
  for (const Filesystem::DirectoryEntry& entry : it) {
    if (entry.type_ == Filesystem::FileType::Regular) {
      auto path = absl::StrJoin({dir, entry.name_}, "/");
      auto [fileInfo, err] = api_.fileSystem().stat(path);
      if (err != nullptr) {
        continue;
      }
      files[entry.name_] = {
        .name = entry.name_,
        .path = path,
        .size_bytes = entry.size_bytes_.value_or(0ul),
        .created_at = fileInfo.time_created_.value_or(SystemTime{}),
      };
    }
  }
  entries_ = std::move(files);
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording