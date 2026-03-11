#!/bin/bash

#{{BASH_RLOCATION_FUNCTION}}
runfiles_export_envvars

readonly CRANE="$(rlocation "{{crane_path}}")"
readonly JQ="$(rlocation "{{jq_path}}")"
readonly MANIFEST_DIGEST_FILE="$(rlocation "{{manifest_digest_file}}")"
readonly REPOSITORY="{{repository}}"
readonly INDEX_TAGS_FILE="$(rlocation "{{index_tags_file}}")"

MANIFEST_DIGEST="$(tr -d '\n' <"${MANIFEST_DIGEST_FILE}")"

if [[ -z "${MANIFEST_DIGEST}" ]]; then
  echo "error: manifest digest file is empty"
  exit 1
fi

index_manifest=""
index_exists=false

function fetch_index() {
  local tag="$1"
  index_manifest=$("${CRANE}" manifest "${REPOSITORY}:${tag}" 2>/dev/null)
  if [ $? = 0 ]; then
    index_exists=true
  else
    index_exists=false
  fi
}

function index_contains() {
  if [ $index_exists = false ]; then
    return 0
  fi
  local contains
  contains=$("${JQ}" '[(.manifests // [])[] | select(.digest == $digest)] | any' --arg digest "$1" <<<"${index_manifest}") || exit 1
  [[ "${contains}" == "true" ]] && return 0 || return 1
}

function update() {
  local tag="$1"
  local retries_remaining=5
  echo "=> updating index ${tag}"
  fetch_index "${tag}"
  if index_contains "${MANIFEST_DIGEST}"; then
    echo "=> index already contains manifest ${MANIFEST_DIGEST}"
    return 0
  fi
  while ((retries_remaining > 0)); do
    if [ $index_exists = true ]; then
      echo "=> creating index"
      "${CRANE}" index append -m "${REPOSITORY}@${MANIFEST_DIGEST}" "${REPOSITORY}:${tag}"
    else
      echo "=> updating existing index"
      "${CRANE}" index append -m "${REPOSITORY}@${MANIFEST_DIGEST}" -t "${REPOSITORY}:${tag}"
    fi
    fetch_index "${tag}"
    if index_contains "${MANIFEST_DIGEST}"; then
      echo "=> index updated successfully"
      return 0
    else
      echo "=> index was not updated successfully (another instance of this script may be running concurrently). retrying"
      # Another instance of this script was running at the same time and overwrote our index update.
      # The other instance will have succeeded, so we can retry immediately
      retries_remaining=$((retries_remaining-1))
    fi
  done
  echo "=> giving up after 5 retries"
  return 1
}

while IFS=$'\n' read -r index_tag; do
  index_manifest=""
  index_exists=false
  update "${index_tag}"
done <"${INDEX_TAGS_FILE}"