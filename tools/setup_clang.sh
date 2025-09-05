#!/usr/bin/env bash

# Copyright The Envoy Project Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

BAZELRC_FILE="${BAZELRC_FILE:-./clang.bazelrc}"

LLVM_PREFIX=$1
LLVM_CONFIG="${LLVM_PREFIX}/bin/llvm-config"

if [[ ! -e "${LLVM_CONFIG}" ]]; then
  echo "Error: cannot find local llvm-config in ${LLVM_PREFIX}."
  exit 1
fi

LLVM_LIBDIR="$("${LLVM_CONFIG}" --libdir)"
PATH="$("${LLVM_CONFIG}" --bindir):${PATH}"

RT_LIBRARY_FILE="$("${LLVM_PREFIX}/bin/clang" --rtlib=compiler-rt --print-libgcc-file-name)"
RT_LIBRARY_PATH="$(dirname "${RT_LIBRARY_FILE}")"

cat <<EOF >"${BAZELRC_FILE}"
# Generated file, do not edit. If you want to disable clang, just delete this file.
build:clang --host_action_env=PATH=${PATH} --action_env=PATH=${PATH}

build:clang --action_env=LLVM_CONFIG=${LLVM_CONFIG} --host_action_env=LLVM_CONFIG=${LLVM_CONFIG}
build:clang --repo_env=LLVM_CONFIG=${LLVM_CONFIG}
build:clang --linkopt=-L${LLVM_LIBDIR}
build:clang --linkopt=-Wl,-rpath,${LLVM_LIBDIR}

build:asan --linkopt=-L${RT_LIBRARY_PATH}
EOF
