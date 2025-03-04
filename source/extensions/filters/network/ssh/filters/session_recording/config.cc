#include "source/extensions/filters/network/ssh/filters/session_recording/config.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording {

REGISTER_FACTORY(SessionRecordingFilterFactory, NamedFilterConfigFactory);
}