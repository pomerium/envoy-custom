#!/bin/bash

#{{BASH_RLOCATION_FUNCTION}}
runfiles_export_envvars

readonly CRANE="$(rlocation "{{crane_path}}")"
readonly MANIFEST_DIGEST_FILE="$(rlocation "{{manifest_digest_file}}")"
readonly REPOSITORY="{{repository}}"
readonly INDEX_TAGS_FILE="$(rlocation "{{index_tags_file}}")"

MANIFEST_DIGEST="$(tr -d '\n' <"${MANIFEST_DIGEST_FILE}")"

if [[ -z "${MANIFEST_DIGEST}" ]]; then
  echo "error: manifest digest file is empty"
  exit 1
fi

while IFS=$'\n' read -r index_tag; do
  "${CRANE}" index append -m "${REPOSITORY}@${MANIFEST_DIGEST}" -t "${REPOSITORY}:${index_tag}"
done <"${INDEX_TAGS_FILE}"