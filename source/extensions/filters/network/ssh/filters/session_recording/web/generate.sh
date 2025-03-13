#!/bin/sh

echo '#include "source/extensions/filters/network/ssh/filters/session_recording/web/assets.h"'
echo 'namespace Envoy::Extensions::NetworkFilters::GenericProxy::StreamFilters::SessionRecording::Web {'
echo 'const std::string_view embedded_asciinema_player_js = R"EOF('
cat "$1"
echo ')EOF";'
echo 'const std::string_view embedded_asciinema_player_css = R"EOF('
cat "$2"
echo ')EOF";'
echo 'const std::string_view embedded_index_html = R"EOF('
cat "$3"
echo ')EOF";'
echo '}'
