# Pomerium Custom Envoy

This repo contains the custom Envoy extensions used in Pomerium, and tooling to compile Envoy with
those extensions statically linked in.

Most of the Bazel configuration and scripts were sourced from https://github.com/envoyproxy/envoy-filter-example and https://github.com/istio/proxy.

## Building

Follow the [Envoy Bazel Install](https://github.com/envoyproxy/envoy/blob/main/bazel/README.md#installing-bazelisk-as-bazel) docs to install bazel.

This repo is configured to build using clang and libc++. The easiest way to install these is using your distro's package manager. Ensure `clang`, `lld`, `lldb`, and `libc++` (on Ubuntu, `libc++1`) are installed.

To build the Envoy static binary:

`bazel build //:envoy`

To build in debug mode:

`bazel build -c //:envoy`

To build using Envoy sources from a local directory:

`bazel build --override_repository=envoy=/path/to/envoy //:envoy`

or, add `common --override_repository=envoy=/path/to/envoy` to a file named `user.bazelrc` in this repo.

## Testing

To run the tests in this repo:

`bazel test //...`

To run the regular Envoy tests from this project:

`bazel test @envoy//test/...`

### Coverage

To run tests with code coverage, create a `bazel` task in `.vscode/tasks.json` as follows:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Test with coverage",
      "type": "bazel",
      "command": "coverage",
      "targets": ["//source/extensions/..."],
      "options": [
        "--instrumentation_filter=.*",
        "--experimental_split_coverage_postprocessing",
        "--experimental_fetch_all_coverage_outputs"
      ]
    }
  ],
}
```

Then, run the task. Coverage info will be displayed in the test explorer view in vscode.

## IDE setup

The following vscode extensions are recommended:

- https://marketplace.visualstudio.com/items?itemName=BazelBuild.vscode-bazel
- https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd
- https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb

Generate `compile_commands.json` by running `tools/vscode/refresh_compdb.sh`.