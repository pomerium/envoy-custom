# Pomerium Custom Envoy

This repo contains the custom Envoy extensions used in Pomerium, and tooling to compile Envoy with
those extensions statically linked in.

Most of the Bazel configuration and scripts were sourced from https://github.com/envoyproxy/envoy-filter-example and https://github.com/istio/proxy.

## Building

To build the Envoy static binary:

`bazel build //:envoy`

To build in debug mode:

`bazel build -c //:envoy`

To build using Envoy sources from a local directory:

`bazel build --override_repository=envoy=/path/to/envoy //:envoy`

## Testing

To run the regular Envoy tests from this project:

`bazel test @envoy//test/...`

## IDE setup

The following vscode extensions are recommended:

- https://marketplace.visualstudio.com/items?itemName=BazelBuild.vscode-bazel
- https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd
- https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb

Generate `compile_commands.json` by running `tools/vscode/refresh_compdb.sh`.