#!/bin/bash

set -e

proto_lib_query='kind(go_proto_library, //api/extensions/...)'

bazel build $(bazel query $proto_lib_query)
output_path=$(bazel info execution_root)
output_files=$(bazel cquery --output=starlark \
  --starlark:expr="'\n'.join(['${output_path}/'+f.path for f in target.output_groups.go_generated_srcs.to_list()])" \
  $proto_lib_query)

for src in $output_files; do
  dest=$(echo $src | sed -e 's|^.*github.com/pomerium/envoy-custom/||')
  cp -f ${src} ${dest}
done
