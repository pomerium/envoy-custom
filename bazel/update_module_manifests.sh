#!/bin/bash

# For each module, updates the source.json manifest with file names and checksums of the contents of
# the "overlay" and "patches" directories in the module.

for source in $(find "$(dirname "$0")/modules" -name "source.json"); do
  dir="$(dirname "$source")"
  echo "updating ${source}"
  for key in "patches" "overlay"; do
    args=()
    if [ -d "${dir}/${key}" ]; then
      for f in $(find "${dir}/${key}" -type f); do
        checksum="sha256-$(openssl dgst -sha256 -binary "$f" | openssl base64 -A)"
        args+=("{\"$(basename "$f")\": \"${checksum}\"}")
      done
    fi
    jq '([$ARGS.positional[]] | sort | add) as $input | if $input then (. + {$key: $input}) else (. | del(.[$key])) end' \
      "$source" --arg key "${key}" --jsonargs "${args[@]}" | sponge "$source"
  done
done