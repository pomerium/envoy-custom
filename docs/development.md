# Pomerium Envoy Developer Docs

# How To Use This Documentation

This document is an introduction to the envoy-custom codebase and how to use it. It covers the high
level structure, build system usage, and Pomerium-specific customizations. It does not document the
code itself.

If you want to work on the code, you should read this document in its entirety.

If you only need to make a one-off build of Envoy and don't need to know all the details or work on
the code, read [Installing Bazel](#installing-bazel) and then skip to [Build](#build).

There is no AI-generated text in this document.

# 1. Repository

## Pomerium Extensions

### SSH

- SSH Filter (`source/extensions/filters/network/ssh`)

  This is a
  [generic proxy](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/generic_proxy_filter)
  filter. It implements the SSH protocol and Pomerium SSH related features.

- GRPC Health Check Event Sink (`source/extensions/health_check/event_sinks/grpc`)

  This is a simple
  [health check event sink](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/health_check_event_sinks/health_check_event_sinks#)
  which sends health check events over grpc. It is part of the reverse tunnels feature.

### Tracing

- Trace Context Injector (`source/extensions/http/early_header_mutation/trace_context`)

  This is a
  [HTTP early header mutation](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/http/early_header_mutation)
  filter. It processes pomerium-specific trace headers to propagate otel trace sampling decisions
  and trace parent info across redirects during oauth authentication flows.

- Trace Request ID (`source/extensions/request_id/uuidx`)

  This is a
  [request ID](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/request_id/request_id)
  extension which extends the default UUID implementation. It works with the trace context injector
  extension to propagate trace sampling decisions.

- Pomerium OTel Tracer (`source/extensions/tracers/pomerium_otel`)

  This is an
  [HTTP tracer](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/trace/trace.html)
  extension. It works with the other trace extensions to propagate pomerium-specific trace headers
  and sampling decisions.

### Other

- Dynamic Extension Loader (`source/extensions/bootstrap/dynamic_extension_loader`)

  This is a [bootstrap](https://www.envoyproxy.io/docs/envoy/latest/api-v3/bootstrap/bootstrap.html)
  filter. Bootstrap filters are initialized shortly after server startup and persist for the
  lifetime of the server. This filter is responsible for loading dynamic extensions.

## Directory Structure

The directories `api`, `source`, and `test` follow a similar pattern for each extension:

`{api|source|test}/extensions/{category[/...]}/{extension_name}`

- `api/`

  Contains protobuf definitions and inline generated Go sources. Each extension generally has its
  own "Config" message which is used to configure it in Envoy. Some extensions have other messages
  for other purposes, e.g. authorization RPC with Pomerium
  - `api/x/`

    Contains protobuf definitions used in out-of-tree extensions.

- `bazel/`

  Contains Bazel starlark code used as part of the build system.

  There are a handful of targets defined in `BUILD` files within this subdirectory, but most of the
  code here is in `.bzl` files. These define reusable rules and macros used in `BUILD` files and in
  `WORKSPACE`.

  Specific subdirectories are covered in the Toolchain and CI sections.

- `patches/`

  Contains git patches applied to dependencies.

- `source/`
  - `source/common/`

    Code shared between extensions. Also contains dynamic extensions library code, ABI definitions,
    and metadata decoder.

  - `source/extensions/`

    Extension source code

- `test/`
  - `test/test_common/`

    Contains shared test code not specific to any extension.

    Tests should almost always #include `test/test_common/test_common.h` directly.

  - `test/upstream/`

    Contains `test_suite` rule definitions which alias upstream test targets. This selects upstream
    tests which will be run when `bazel test //test/...` is invoked (manually or in CI).

  The `common/` and `extensions/` subdirectories in `test/` mirror those in `source/`.

- `tools/`

  Contains miscellaneous scripts.

  Also contains the `read-extension` CLI tool which is used to inspect and troubleshoot dynamic
  extensions.

### Top-level files

<a name="bazelrc" ></a>

- `.bazelrc` , `envoy.bazelrc` , `pomerium.bazelrc`

  These contain workspace-specific bazel default flags for different bazel subcommands.

  The syntax and behavior of these files is peculiar and sparsely documented. Generally, putting a
  flag in the bazelrc makes it act as if you had explicitly written that flag on the command line.

  Flags are prefixed by a selector which tells bazel what situations the flags should apply in. The
  syntax of the selector is `<command>[:<config-key>]` . The command name corresponds to the bazel
  top level subcommand being used (e.g. `build` adds flags to `bazel build`, `test` adds flags to
  `bazel test`). There is also a special `common` command name which applies flags to all bazel
  commands and a `startup` command name which is used for some bazel meta-options.

  The config keys can be used in two ways:
  - Coarse filtering based on _host_ platform (the platform on which bazel is actually being
    invoked). The special keys `linux` and `macos` can be used here.

    Every use of platform selectors in bazelrc is a hack and should be considered tech debt (in
    fact, this applies to most uses of bazelrc). This is because the bazelrc platform selectors are
    not aware of [Platforms](https://bazel.build/extending/platforms) and do not work as expected in
    many cases.

  - Filtering based on _user-defined_ config keys. These keys are selected when you pass the flag
    `--config=<key>` on the command line or in another bazelrc rule.

    Most of the user defined config keys we use are ones defined in the vendored upstream
    `envoy.bazelrc` file. These include `coverage` `asan` `clang` etc.

    The config keys are arbitrary (other than the reserved ones) and don't need to be defined
    somewhere ahead of time.

  Avoid adding new entries to `pomerium.bazelrc` if possible.

- `user.bazelrc`

  This is an optional gitignore'd file which can hold user-specific bazel options. Use this to
  configure any bazel defaults for your environment.

- `WORKSPACE`

  Bazel workspace definition. This uses the legacy bazel workspaces feature (because upstream envoy
  does, although they are in the process of migrating to bzlmod).

  Note that the most recent versions of the bazel documentation (9.0+) have removed some of the
  information about the legacy workspace system and `WORKSPACE` files. Documentation for version 7.7
  is no longer directly linked on the official site but can be accessed by changing the version
  number in the url path.

- `BUILD`

  Contains top level build targets.

  There is a `BUILD` file in every subdirectory that contains code. The one at the workspace root
  contains the main `envoy` target and other top-level build targets.

  Some `BUILD` files are empty, usually when a directory only contains `.bzl` starlark code to be
  imported elsewhere and no actual build targets. The empty `BUILD` files are required by bazel and
  serve as markers for packages (similar to how Go treats directories that contain .go sources vs
  directories that don't).

# 2. Setup

## Installing Bazel

You should only ever interact with bazel by using https://github.com/bazelbuild/bazelisk. Install it
using your package manager if available (arch and homebrew have it, ubuntu does not). Otherwise
download the binary and put it in `/usr/local/bin/bazel` (you should rename the binary to `bazel`).
It can also be obtained via `go install github.com/bazelbuild/bazelisk@latest` but this will leave
the binary named `bazelisk` so you'll need to create a symlink afterwards in ~/go/bin.

Bazelisk will automatically download the version of bazel specified in `.bazelversion` in the repo.

## VSCode Extensions

Use the following vscode extensions:

- Clangd
  [https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd](https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd)
- LLDB DAP
  [https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.lldb-dap](https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.lldb-dap)
- Protobuf language server
  [https://marketplace.visualstudio.com/items?itemName=kralicky.protols-vscode](https://marketplace.visualstudio.com/items?itemName=kralicky.protols-vscode)
  (see [Protobuf Generated Code](#protobuf-generated-code) for details)

Do NOT use:

- Microsoft C/C++ (incompatible with clangd)
- CodeLLDB (incompatible with lldb dap)

Optionally you can also use the Bazel extension, but it has a lot of missing features. I have a fork
of vscode-bazel here: https://github.com/kralicky/vscode-bazel which has several extremely useful
features that are mostly specific to this repo but make development much easier.

## VSCode Workspace Setup

1. Configure `.vscode/settings.json`

   ```jsonc
   {
     // Adds code lenses to bazel rules in BUILD files (optional)
     "bazel.enableCodeLens": true,

     // Extra args passed to bazel test commands invoked from the target explorer.
     // Use as needed
     "bazel.extraTestArgs": [
       // "--log-level debug",
     ],

     "clangd.arguments": [
       // Required
       "--clang-tidy",
       "--all-scopes-completion",
       "--query-driver=**",
       "--resource-dir=${workspaceFolder}/external/llvm_toolchain_llvm/lib/clang/22",
       // Optional but recommended
       "--pch-storage=memory",
       "--header-insertion=iwyu",
       "--header-insertion-decorators",
       "--rename-file-limit=200",
       "--log=error",
     ],

     // Replace <path> below with the absolute path to the workspace folder.
     // (lldb-dap doesn't expand ${workspaceFolder} here, this can be fixed when https://github.com/llvm/llvm-project/pull/183989 is merged)
     "lldb-dap.executable-path": "/<path>/external/llvm_extras_linux_amd64/bin/lldb-dap",

     // Optional but recommended
     "editor.rulers": [
       {
         "column": 100,
         "color": "#ABB2BF50",
       },
     ],
   }
   ```

2. Configure `.vscode/launch.json`. The following configuration is useful to attach to a running
   Envoy process managed by Pomerium (when building Envoy locally and building Pomerium with the
   debug_local_envoy build tag)

   ```jsonc
   {
     "version": "0.2.0",
     "configurations": [
       {
         "name": "Attach",
         "type": "lldb-dap",
         "request": "attach",
         "program": "${workspaceFolder}/bazel-bin/envoy",
         "pid": 0,
         "sourceMap": {
           "/proc/self/cwd": "${workspaceFolder}",
         },
       },
     ],
   }
   ```

3. Obtain the debugger package for your arch:

   ```bash
   $ bazel fetch @llvm_extras_linux_amd64//:all # for linux/amd64
   $ bazel fetch @llvm_extras_linux_arm64//:all # for linux/arm64
   ```

   Note that if you run `bazel clean`, you will need to re-run this command again.

## User Bazelrc Options

It is recommended to explicitly specify your host platform in `user.bazelrc` by adding the
following: `common --host_platform=//bazel/platforms/rbe:linux_x64 # or linux_arm64 or macos`

Some useful options to put here:

<a name="sandbox-base"></a>

- `common --sandbox_base=/dev/shm`

  This tells bazel to store build artifacts and intermediate outputs in `/dev/shm` which is always a
  tmpfs on Linux. You can also use `/tmp` (or any other directory) but `/tmp` is often not actually
  backed by ram. This significantly speeds up builds (sandboxes are temporary and often contain
  thousands of files and symlinks), but requires a lot of memory.

<a name="experimental-platform-in-output-dir"></a>

- `common --experimental_platform_in_output_dir`

  This causes the subdirectory names in `bazel-out` to also contain the OS name (`linux` or `macos`)
  in addition to the arch. This is important if you plan to test cross-compiling builds locally. If
  you build for different platforms with the same arch, for example `linux_arm64` and `macos`, the
  outputs will end up in `bazel-out/linux_arm64-<mode>/` or `bazel-out/macos-<mode>/` respectively.
  Without this flag, builds for both platforms would write their outputs to the same directory,
  discarding cached builds for whichever platform was built previously.

## Disk Cache

If you need to build Envoy on a regular basis you should set up a disk cache, but come back to this
section after reading [The `external` Directory](#the-external-directory) in the next section.

### Setting up a Disk Cache

1. Choose a suitable directory for long-lived persistent data

   This should not be in `~/.cache/bazel` , which is where the workspace output directories live.
   You can put it nearby, for example `~/.cache/bazel_disk_cache` but be careful not to confuse
   future you who might have to come back to this later after running out of disk space and probably
   won't remember which directory is which.

   It might be advisable to choose a location on the same filesystem as your home directory, but
   whether this improves performance or not depends on the particular filesystem.

   Alternatively, using a separate partition/disk or a network share for the cache has some
   advantages. When the cache inevitably runs out of disk space, it will be easier to deal with if
   the cache is not part of your live root or home partition. Some of the performance losses can be
   offset using [`--sandbox_base=/dev/shm`](#sandbox-base) described above if you have memory to
   spare.

2. Create subdirectories for the disk and repository caches

   Create separate directories under the top level directory you chose for the cache. For example,
   `/path/to/bazel-cache/disk` and `/path/to/bazel-cache/repository`.

   The repository cache is less important than the disk cache, but it is still wiped out if you run
   `bazel clean --expunge` so it's worth separating. It caches artifacts downloaded from the
   internet, such as source tarballs for git dependencies or toolchain binaries. These are shared
   across workspaces.

   The disk cache (which is just an implementation of a bazel remote cache backed by disk) stores
   build outputs. It is much more complicated than the repository cache but it's not important to
   know exactly how it works internally. Build outputs from the cache can be downloaded and reused
   if the inputs are the same. If you clean your bazel output directory with
   `bazel clean [--expunge]` , most of the build outputs can still be re-downloaded from the disk
   cache on the next build.

3. Configure `$HOME/.bazelrc`

   Create a `.bazelrc` file in your home directory for this configuration, since it is not
   workspace-specific. Bazel also looks in `/etc/bazel.bazelrc` if system-wide configuration is
   preferred.

   The contents of the file should be:

   ```bash
   # replace /path/to/bazel-cache with your own path
   build --disk_cache=/path/to/bazel-cache/disk
   build --repository_cache=/path/to/bazel-cache/repository
   build --experimental_disk_cache_gc_max_age=30d # adjust to preference
   ```

### Important Caveats

#### Disk Usage

The disk cache uses a lot of space. It is recommended to allocate at least 1TB to the cache. If it
runs out of space, you will need to use this tool to manually perform garbage collection:
https://github.com/bazelbuild/bazel/tree/master/src/tools/diskcache or delete the entire cache, if
it can't otherwise be resized.

#### Fission

Envoy uses [fission](https://bazel.build/docs/user-manual#fission) for debug builds. When building
in debug mode, most of the debug info from compiled object files is split into separate `.dwo`
files. These dwo files are not linked into the resulting binary. Instead, the paths to the dwo files
(which live somewhere in the bazel output tree) are stored.

When object files are pulled from a remote cache instead of building them locally, the corresponding
dwo files may not always be fetched if they are not required to build the requested binary. If you
then try to debug this binary, and the dwo files weren't downloaded from the remote cache, most of
the debug info won't be available, and it will not be obvious what is going on. You will likely get
dwarf-related errors from the debugger which can be a hint that the dwo files are missing.

To avoid this, either:

- Build with the flag `--remote_download_all` which will force the dwo files to be downloaded from
  the cache if they are missing locally
- After building a binary target (e.g. `//:envoy` , build the same target with `.dwp` appended to
  the name (e.g. `//:envoy.dwp`). This creates a file named `envoy.dwp`, which contains all the
  individual `.dwo` files created during a build merged into a single package. The `.dwo` files are
  required to create the `.dwp`, so they _will_ be downloaded from the remote cache if needed. All
  cc_binary targets have a corresponding dwp target; this is not specific to envoy. Note that the
  `envoy` binary itself is not a dependency of `envoy.dwp`, so you have to tell bazel to build both.

# 3. Building

## Important Bazel Topics

### How to read the official Bazel documentation

The official bazel documentation is, for the most part, pretty good. It can be difficult to navigate
though.

The documentation is dense and it is easy to want to skip around. Because of this it is easy to
accidentally develop an incorrect mental model of how bazel really works, which can make reading the
documentation for the more advanced topics feel frustrating.

Many pages in the bazel documentation will tell you up front that you should read some other page(s)
first before reading this one. Do not ignore these suggestions.

### Terminology: Targets, Labels, Rules

Bazel docs: [Targets](https://bazel.build/reference/glossary#target),
[Labels](https://bazel.build/reference/glossary#label), [Rules](https://bazel.build/extending/rules)

Consider the following workspace:

```
./
  WORKSPACE
  source/
    foo/
      BUILD
      bar.cc
```

```py
workspace(name = "example")

# ... unimportant setup for toolchains etc ...
```

```py
load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

# cc_binary is a rule. It is used below to create a target named "bar".
# The target can be referenced using the label '//source/foo:bar'.
cc_binary(
  name = "bar",
  srcs = ["bar.cc"],
)
```

```cc
#include <iostream>

int main(int argc, char** argv) {
  std::cout << "hello world" << std::endl;
}
```

In the above example you could build the `bar` binary by running

```bash
$ bazel build //source/foo:bar
```

If you run this from the workspace directory or a subdirectory within the workspace, then you don't
have to use the fully qualified label which includes the repository name: `@example//source/foo:bar`
(the repository name `example` is defined in `WORKSPACE` above); omitting the `@<repository name>`
prefix implies the current repository.

Within a target definition in a `BUILD` file, it is common to refer to other targets defined in the
same file using the syntax `:some_rule_name`. When referring to targets in a different `BUILD` file,
labels must use the full path starting with `//`.

When referring to targets defined by external dependencies, the label must be qualified with that
dependency's repository name (e.g. `@some_dependency//bar:baz`), otherwise Bazel will assume the
target is from the current repository.

Another common shorthand you might see is `@foo//bar` with no trailing `:name` identifying the
target. In this case, the target name is assumed to be the same as the last section of the label, so
`@foo//bar` is the same as `@foo//bar:bar`. This also works with repository names; the label `@foo`
by itself refers to the target `@foo//:foo`.

Lastly, the target name `all` is reserved. For example `//foo:all` refers to all targets defined in
`./foo/BUILD` in the current workspace. You can also use `//foo:*` or the recursive `//foo/...`
which works like it does in Go.

### Compilation Modes

Bazel docs: https://bazel.build/docs/user-manual#build-semantics

Prerequisite reading:

- `assert` and `NDEBUG`: https://en.cppreference.com/cpp/error/assert

There are 3 bazel compilation modes: `dbg` (debug), `opt` (optimized) and `fastbuild`.

The compilation mode is controlled with the `-c` flag (short for `--compilation_mode`). This is not
to be confused with `--config`, which is something else entirely (see [bazelrc](#bazelrc)) and does
not have a short flag.

Bazel will define `NDEBUG` ("no debug") in `opt` mode only. This disables most asserts and any other
code guarded by `#ifndef NDEBUG`. Note that Envoy has some assert macros which remain active in
release builds.

`dbg` and `opt` modes are mostly self-explanatory. `fastbuild` should generally be avoided. It's not
that much faster and without debug symbols it's mostly useless for development. If you don't provide
the `-c` flag explicitly then `fastbuild` is the default. This means you should almost always
explicitly specify if you want `-c dbg` or `-c opt` when invoking bazel, lest you accidentally
rebuild everything.

Each compilation mode operates on a different set of build outputs. This is important; if a target
was built with `-c dbg`, building it again with `-c opt` (or `-c fastbuild` / omitting `-c`) will
trigger a complete rebuild of that target. You will end up with two separate build outputs, one for
dbg and one for opt. Switching to `-c dbg` again will use the previously cached debug build though.

### Output Directories

Bazel docs: https://bazel.build/remote/output-directories#layout-diagram

When you run bazel build for the first time (or after running `bazel clean`), it will create a few
directory symlinks in the workspace. These are `bazel-out`, `bazel-bin` , `bazel-testlogs`, and
`bazel-<workspace name>`. These are sometimes called "convenience symlinks" in the bazel docs.

These symlinks are very useful but can have surprising behavior so it is useful to know what each
one does:

- `bazel-out`

  This is a symlink to the location where build outputs are placed for this workspace. By default
  this is somewhere within `~/.cache/bazel` in a unique directory for this workspace (based on a
  hash of the workspace's path on disk).

  Within `bazel-out/` are separate directories for each compilation mode. By default the directories
  look like `<arch>-<mode>` but this can be adjusted to improve cross compiling workflows (see
  [`--experimental_platform_in_output_dir`](#experimental-platform-in-output-dir))

  For example: by default, on a linux/amd64 host, building with `-c dbg` would write outputs to
  `bazel-out/k8-dbg/` and building with `-c opt` would write outputs to `bazel-out/k8-opt/`. "k8" is
  another name for amd64, not to be confused with k8s.

  All data in `bazel-out` is deleted when running `bazel clean`. Note that `bazel clean` does _not_
  delete the contents of `external` (described below) unless you pass the `--expunge` flag, which
  deletes the entire workspace output directory.

- `bazel-bin`

  This is equivalent to `bazel-out/<mode>/bin/` for whichever compilation mode was most recently
  used in a bazel command. This directory changes every time you run bazel with a different
  compilation mode. This is annoying but can be important for some use cases like binary paths in
  debug configurations because the exact `<mode>` directory names depend on environmental factors.
  Of course, you can always use `bazel-out/<mode>/bin/` instead.

- `bazel-testlogs`

  Stores test logs.

- `bazel-<workspace name>`

  Symlink to one level above `bazel-out`.

### The `external` Directory

In addition to the standard convenience symlinks, a symlink (not the directory itself) called
`external` is created by the tool that generates the compilation database. It is a symlink to a
directory where "external dependencies" are stored. This is workspace-specific and is not shared
with other workspaces, but it _is_ shared across compilation modes.

The `external` directory does _not_ work like `~/go/pkg/mod`. It is better to think of this like an
extension of the workspace itself; git repo contents for dependencies are stored here (in place of,
say, git submodules), and the top level subdirectories of the external folder are treated as bazel
repositories which are referenced by name using `@<name>` syntax in labels.

You can also create virtual repositories here containing build rules and other arbitrary files
generated using information only known at build time (like the host platform). This is how the
toolchains are set up, for example.

<b>Warning:</b> files in `external` are editable, and if you edit them bazel will not know about it
(this can be both a good and bad thing). If you delete a folder in `external` manually, things will
break. As far as I know there is no easy way to force bazel to "fix" the external directory other
than deleting the entire workspace output tree via `bazel clean --expunge` and starting over from
scratch. Because this is sometimes necessary, it is _strongly_ recommended to set up a disk cache so
that you won't have to rebuild everything if you ever need to run this command.

If you skipped the [Disk Cache](#disk-cache) section before, now is a good time to go back to it and
set that up.

## Supported Platforms

We support 3 platforms:

- Linux amd64
- Linux arm64
- Macos arm64

Some features, such as dynamic extensions, are currently not supported on macos.

## Build

### Host Dependencies

The only host dependency right now is `libxml2`. This is because the prebuilt `lld` (llvm linker)
binaries dynamically link to it. This is a known issue.
https://github.com/bazel-contrib/toolchains_llvm/issues/657

The binaries could be patched to fix this but so far it's not really a big issue and doesn't affect
the build itself.

### Building Envoy

`bazel build -c {dbg|opt} //:envoy`

There are several envoy targets that build the binary in different ways:

| Target                     | Output                                                                                           | Size (`opt`) | Size (`dbg`) |
| -------------------------- | ------------------------------------------------------------------------------------------------ | ------------ | ------------ |
| `//:envoy`                 | Dynamically linked `envoy` binary with runtime dependency on glibc. Supports dynamic extensions. | 394M         | 942M         |
| `//:envoy.static`          | Fully static `envoy` binary with no runtime dependencies. Does not support dynamic extensions.   | 361M         | 859M         |
| `//:envoy.stripped`        | `//:envoy` with symbols stripped                                                                 | 112M         | 358M         |
| `//:envoy.static.stripped` | `//:envoy.static` with symbols stripped                                                          | 80M          | 275M         |
| `//:envoy.dwp`             | Debug info package for `//:envoy`. See [Fission](#fission)                                       |              | 2.4G         |
| `//:envoy.static.dwp`      | Debug info package for `//:envoy.static`. See [Fission](#fission)                                |              | 2.4G         |

### Building Images

The `//:envoy` and `//:envoy.static` targets also have corresponding image targets which build OCI
images.

The targets below are used with `bazel run`, not `bazel build`.

| Target                                                                    | Actions                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `//:update_index.envoy.image` <br /> `//:update_index.envoy.static.image` | 1. Builds `//:envoy` or `//:envoy.static` (depending on the target) <br /> 2. Packages the binary into an OCI image <br /> 3. Pushes the image (untagged) to the remote repository <br /> 4. Updates the multi-arch OCI index (tagged) to set the image for the arch that was just built to the digest of the image pushed in (3).                                                                                                         |
| `//:docker_load.envoy.image` <br /> `//:docker_load.envoy.static.image`   | 1. Builds `//:envoy` or `//:envoy.static` (depending on the target) <br /> 2. Packages the binary into an OCI image <br /> 3. Loads the image into the local docker daemon. <br /> IMPORTANT: This should only be used for debug purposes. The process of loading the image into the docker daemon changes the format in a way that makes it unsuitable for distribution. The image loaded in this way will not work with `get-envoy` etc. |

For debugging purposes, `bazel build //:update_index.envoy.image` (not `bazel run`) can be used.
This command will output the path of the shell script which performs the image upload task. It does
not run the script unless you use `bazel run`. It will also have built the oci-layout directory and
compressed oci tarball for the image. These can be found at `bazel-bin/_envoy.image_img/` and
`bazel-bin/_envoy.image_tar.tar.zst` respectively.

## Compilation Database

IDE support requires generating a `compile_commands.json` file which contains the compiler args used
to build each source file.

To generate this file, first build Envoy in debug mode (`bazel build -c dbg //:envoy`). Then, run
`bazel run //:refresh_compile_commands -- -c dbg` . This takes a couple minutes and may print out a
bunch of warnings which can be ignored.

Afterwards, restart clangd from vscode using the `clangd: Restart language server` vscode command.

The first time this is run, clangd will run a full index task in the background which takes a while.
When refreshing the compile commands in the future, it will not re-index everything again, only
files that have changed. The index cache is stored in the workspace in the `.cache/` folder.

### Troubleshooting

There are some cases where clangd still doesn't work even after generating the compile commands. The
most common issue is mismatched compilation modes when building Envoy and generating the compilation
database.

`compile_commands.json` contains workspace-relative paths to intermediate build artifacts (`.o` and
`.d` files) which are expected to exist on disk. These files are located within `bazel-out/<mode>/`
for a specific mode. This mode is selected based on the flags passed to the refresh compile commands
tool after the `--` . For example, `bazel run //:refresh_compile_commands -- -c dbg` will encode
`bazel-out/<os-arch>-dbg/` paths into the compilation database. Generating the compilation database
does not build Envoy, it only queries bazel to see what commands would be run.

If the mode passed to refresh_compile_commands is not the same mode that was used to build Envoy
beforehand, these files will not exist.

Additionally, the same problems described in [Fission](#fission) can occur here as well: the
intermediate build artifacts may not be downloaded from disk cache in all cases if they are not
needed to build the outputs of the requested target. If you build Envoy with `--remote_download_all`
it will fetch these artifacts if they are missing. This can be done retroactively if needed.

## Cross-compiling

All supported platforms can be built on linux/amd64 hosts by cross-compiling. This is how
multi-platform builds currently work in CI.

Platforms are controlled by two command line flags:

- The `--host_platform` flag is passed to `bazel build` to select the _host_ platform, or the
  platform on which the binary will be built.
- The `--platforms` flag is passed to `bazel build` to select the _target_ platform, or the platform
  on which the resulting binary should be runnable on.

It is good practice to always pass `--host_platform`. This should be done from `user.bazelrc`.
`--platforms` is not necessary unless the target platform differs from the host platform (i.e. you
are cross compiling).

The value passed to each of these flags is project-specific. For envoy-custom, the only platform
labels you should use are:

- `//bazel/platforms/rbe:linux_amd64`
- `//bazel/platforms/rbe:linux_arm64`
- `//bazel/platforms/rbe:macos`

Do not use any other platform labels. These labels are opaque to bazel. The names of the labels are
arbitrary and do not ipso facto correspond to an actual platform, but they do have special meaning
in some contexts in our own builds.

Note: the package name "rbe" stands for "remote build execution", but the label is not specific to
remote builds. The naming was kept to match the corresponding names of upstream Envoy's platform
labels (but this should probably be changed in the future since it is confusing).

## Protobuf Generated Code

Protobuf C++ generated sources (`*.pb.{h,cc}` , `*.pb.validate.{h,cc}`) are referenced as if they
were present in the sources next to the corresponding `.proto` files. For example, the code
generated from `api/extensions/filters/network/ssh/ssh.proto` is included as
`#include "api/extensions/filters/network/ssh/ssh.pb.h"` . These files actually live in
`bazel-out/<mode>/bin/api/extensions/filters/network/ssh/` .

Go generated sources not used directly in envoy-custom anywhere. The envoy-custom repo is a go
module, which is imported by Pomerium. The generated Go sources are checked in to git and updated
manually whenever the protos are updated.

The Go generated sources are complicated for several reasons. First, Bazel does not let you copy
generated code back out into the source tree. It goes to great lengths to prevent you from being
able to do this as part of a bazel rule. Copying generated code back into the source tree can only
be done manually after a build. Furthermore, generating the Go protobuf sources from within Bazel is
problematic because some global options specified in the bazelrc files (ours and upstream envoy's)
which are intended for C++ usage end up poisoning the Go toolchain's configuration and causes some
go binaries (like the protoc-gen-validate tool) to be built incorrectly. This is an extremely
difficult problem to solve as it ultimately requires fixing all the issues that use workarounds in
the form of global bazelrc options. These workarounds are mostly related to foreign_cc dependencies
(dependencies that build with cmake/autotools) and can't reasonably be fixed until upstream Envoy
migrates to bzlmod which will allow building these dependencies using native bazel rules from the
[BCR](https://registry.bazel.build/). In the mean time, the workaround is to use the protobuf
language server vscode extension to generate the go sources after modifying the protos. It will
place the generated code in the correct locations next to the protos in the source tree. This
process is not ideal, but it will be improved over time.

# 4. Testing

## Running Tests

Use `bazel test` to run tests. It is recommended to run tests in `dbg` mode so that you can run them
in a debugger if there is a test failure. Avoid running tests in `opt` mode, since most asserts will
be compiled out. `fastbuild` mode can also be useful in some cases, since it keeps asserts enabled
and produces smaller binaries. The debug test binaries can get _very_ large and there are a lot of
them.

## Sanitizers

<b>Warning: do not use these options until setting up a disk cache!</b>

There are several available sanitizer configurations which build the tests with different types of
debugging instrumentation. These configurations are controlled by the `--config` bazel command line
flag:

- `--config=asan` : builds with
  [Address Sanitizer](https://clang.llvm.org/docs/AddressSanitizer.html),
  [UB Sanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html), and
  [Leak Sanitizer](https://clang.llvm.org/docs/LeakSanitizer.html)
- `--config=tsan` : builds with [Thread Sanitizer](https://clang.llvm.org/docs/ThreadSanitizer.html)
- `--config=msan` : builds with [Memory Sanitizer](https://clang.llvm.org/docs/MemorySanitizer.html)

  Note that msan is not used in CI because it reports a lot of issues from C dependencies (things
  that are out of our control, like uninitialized variables in boringssl or openssh etc.).
  Suppressing these warnings is currently not possible due to limitations with the version of Bazel
  that Envoy uses (and even then, configuring the ignorelist is a prohibitively difficult and time
  consuming process).

Only one of these options can be used at a time. Additionally, these options trigger a full rebuild,
as this will instrument _everything_ (including some bootstrapped toolchain binaries, which can be
surprising). Do not use these options until setting up a disk cache, otherwise, switching between
them will wipe out your entire build every time.

## Coverage

Coverage instrumentation functions in a similar way to sanitizer instrumentation, but is enabled
with the `bazel coverage` command instead of `bazel test --config=`.

Run `bazel coverage ./test/...` to generate a combined coverage report from all tests.

It is not necessary to set a compilation mode when using `bazel coverage` .

### IDE Support

The Bazel vscode extension is very useful for viewing coverage reports, but it only works if the
coverage action is invoked using a specific type of task. Add the following to `.vscode/tasks.json`
then run the task with the `Tasks: Run Task` vscode command:

```jsonc
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "coverage: all",
      "type": "bazel",
      "command": "coverage",
      "targets": ["//test/..."],
      "group": "test",
      "problemMatcher": [],
    },
  ],
}
```

When the task is completed, open the Test Explorer (if you can't find it or have it hidden use the
command `Testing: Focus on Test Explorer View`) and the results will be displayed after a few
seconds.

The coverage report displays line coverage and function coverage. Function coverage occasionally
shows <100% even if line coverage is 100%. This can be legitimate, such as a function template not
being called for some specialization, but most of the time these are false negatives caused by
things like delegating constructors or an overloaded function where one overload calls the other
overload. Clicking the dropdown arrow by a source file will show a list of functions and whether it
thinks they have been called or not, so it is easy to figure out what the cause is.

Branch coverage doesn't work currently, which is a known issue. Branch coverage is unfortunately not
as useful as it could be due to the frequent usage of logging and assert macros, both of which
introduce branches. There isn't a good way to exclude these from branch coverage at the moment.

## Upstream Tests

Not all upstream tests work out of the box. We disable a lot of builtin extensions that are unused
in Pomerium, and while there is a mechanism in envoy to skip tests for disabled extensions, it is
not used everywhere, so simply running `bazel test @envoy//test/...` won't work. Most tests do work
though. You can run them using the `@envoy` repository prefix. For example
`bazel test @envoy//test/filters/http/...`

Because upstream has so many tests, it is a good idea to build the test binaries first using
`bazel build` , then run them with `bazel test` separately. Not all tests are strictly
single-threaded so building and running a large collection of tests in parallel can cause major
resource contention. For this reason you might also want to reduce the number of parallel test
targets that run with `--jobs` which otherwise defaults to the number of cores. This might also help
when running envoy-custom tests as well, but upstream has one or two orders of magnitude more test
targets by comparison.

# 5. Debugging

## Attaching to a running Pomerium instance

The easiest way to debug Envoy is by attaching to a running instance managed by Pomerium.

The release binaries that Pomerium normally fetches as part of the build process are built in `opt`
mode and are not suitable for debugging. Instead, first build envoy in `dbg` mode, then build
Pomerium with `make build-local DEBUG_LOCAL_ENVOY_PATH=/path/to/your/envoy-custom/bazel-bin/envoy` .
When running Pomerium it will then use the envoy binary at that path.

Use the debug configuration that was set up in [VSCode Workspace Setup](#vscode-workspace-setup) to
attach to the running envoy process.

Note: if envoy is paused at a breakpoint and pomerium is killed, the envoy subprocess will remain
stuck and it will have to be killed with kill -9.

## Debugging Tests

Debugging individual tests manually is very tedious. You can use our forked vscode-bazel extension
linked in [VSCode Extensions](#vscode-extensions) to make this a lot easier. If you are using this
version of the extension, the bazel target explorer (one of the collapsible sections in the regular
file tree panel) will allow you to right click on a test target and debug it. Additionally you can
click the dropdown arrow next to any test target to see a list of all individual test cases for that
test target (this takes a few seconds to load most of the time), and select a specific test case to
debug using the context menu.

This context menu also has other options for running tests with different sanitizer modes or with
coverage. Running tests with the coverage mode in this way will show the coverage report in the test
explorer.

# 6. Toolchain

Currently, the only supported compiler is Clang. The LLVM toolchain used to build envoy is
"hermetic", meaning the toolchain binaries (compiler, linker, etc.) and all dependencies are
obtained automatically as part of the build, and no host tools are used.

## `toolchain-utils` repository

The LLVM toolchain binaries are obtained from the llvm-project github releases, but the release
tarballs they publish contain _everything_, which is about 12 GB of binaries per os/arch. The xz
compression used for those tarballs is also unfortunately handled by bazel using a legacy
single-threaded implementation in a way that can't easily be swapped out, resulting in the toolchain
download+decompress step taking upwards of 5 minutes (though the size of the archive itself is the
bigger issue anyway). Furthermore, cross-compiling using these archives would require downloading
the full archive for every target arch, even though only a few very small libraries from each
archive are required to build the non-native targets.

For these reasons, using the regular llvm release tarballs causes several issues with CI, and remote
builds specifically, and generally slows down development. Instead, we have automation in place in
the https://github.com/pomerium/toolchain-utils repo to extract the large release tarballs and
repackage them into much smaller archives containing only the tools that are actually required, and
with much more efficient zstd compression.

The binaries are split up into several different archives, which are used for different purposes.
Not every build/platform requires all of these packages, so only the necessary tools are downloaded.

## Toolchain Packages

### Minimal Toolchain Package

This is the main package that contains the toolchain binaries used for the build.

Manifest definition: https://github.com/pomerium/toolchain-utils/blob/main/manifests/llvm-linux.tpl

### Cross-compilation Libraries

This package contains a handful of small libraries and object files used to link binaries for
non-native architectures.

Manifest definition:
https://github.com/pomerium/toolchain-utils/blob/main/manifests/cxx-cross-libs-linux.tpl

### Extras (debuggers)

This package contains "extra" tools not used as part of the build. Currently it only contains the
lldb debugger binaries, including the `lldb-dap` binary which is required for the lldp-dap vscode
extension. This binary is not automatically downloaded by the lldb-dap extension and must otherwise
be obtained manually (see https://lldb.llvm.org/use/lldbdap.html#procuring-the-lldb-dap-binary).

See [VSCode Workspace Setup](#vscode-workspace-setup) for the bazel command used to download this
package. As it is not directly required for the build, it is not downloaded automatically. The tools
that are downloaded from this package are from the same release archive as the rest of the
toolchain, so it is highly recommended to use these binaries to minimize any potential issues that
could be caused by using an older version of the debugger obtained e.g. from your system package
manager.

Manifest definition:
https://github.com/pomerium/toolchain-utils/blob/main/manifests/llvm-extras-linux.tpl

### Macos Utils

This package contains llvm implementations of some commonly used macos build tools. Some of these
tools are used as part of the macos cross compilation workflow.

Manifest definition:
https://github.com/pomerium/toolchain-utils/blob/main/manifests/llvm-macos-utils-linux.tpl

### Sysroots

A pre-built sysroot (small filesystem used in place of `/` by the toolchain) is also provided for
each supported platform. This is an important part of the hermetic build, since it ensures no host
libraries or headers are used. The sysroots are built (somewhat inefficiently) using docker, also as
part of a toolchain-utils CI workflow.

The Linux sysroot contains only glibc (and its dependencies) and libxml2. It is not a container
image, but only a collection of libraries and header files in a standard filesystem layout. The
dockerfile used to build the Linux sysroot is here:
https://github.com/pomerium/toolchain-utils/blob/main/sysroot.dockerfile

The macos sysroot is different; it is extracted from an official macos sdk archive. The manifest for
this sysroot is here:
https://github.com/pomerium/toolchain-utils/blob/main/manifests/sysroot-macos.txt

# 7. Differences from Upstream

## Dependencies

Currently, there are no changes to upstream dependencies.

Additional dependencies used in envoy-custom:

- https://github.com/openssh/openssh-portable

  Used for some cryptographic operations, like packet ciphers and ssh key loading/signing.

- https://github.com/Neargye/magic_enum

  Used for logs

- https://github.com/cameron314/readerwriterqueue

  Used in the implementation of reverse tunnels

- https://github.com/p-ranav/argparse

  Used for [`read-extension` CLI](#read-extension-cli)

## Builtin Extensions

envoy-custom only includes a subset of all available upstream extensions, as not all extensions are
used in Pomerium. This list can be found in `bazel/envoy_build_config/extensions_build_config.bzl`
(https://github.com/pomerium/envoy-custom/blob/main/bazel/envoy_build_config/extensions_build_config.bzl).
The disabled extensions are commented out to make it easier to compare with the upstream
configuration.

## Supported Platforms

Upstream Envoy supports a lot of different platforms, but the only ones we support are listed here:
[Supported Platforms](#supported-platforms)

## Toolchains

Upstream Envoy supports both GCC and Clang toolchains (mostly). This, of course, introduces a lot of
complexity into their build infra which is not necessary for our use cases. To simplify things, we
only use Clang. This is mostly because Clang is a native cross-compiler, meaning the single clang
binary for the host platform can emit code for any target platform (similar to the go compiler for
example). Cross-compiling with GCC is non-trivial, and requires separate toolchains for each
platform.

Additionally, we only support building with libc++/compiler-rt/libunwind (which are part of the llvm
toolchain), not libstdc++/libgcc_s (which are part of gcc). This makes some aspects of the hermetic
toolchain easier, since these libraries are shipped with LLVM, but libstdc++ and libgcc_s would have
to be obtained from the sysroot. These libraries are mostly interchangeable since they implement a
standard ABI, but using the LLVM runtime libraries with other LLVM tools has other advantages.

## Luajit

Lua is a special case. It is built from source, as all envoy dependencies are, but the build process
is not simple. It is a multi-stage process that involves bootstrapping custom build tools and code
generators which produce several of the C source files that are ultimately compiled into the luajit
library and/or interpreter binary. This is a platform-specific process and luajit has its own
cross-compilation workflow.

Cross-compiling luajit using foreign_cc and the regular makefile could not be made to work with the
hermetic toolchain, so we have our own native bazel rules for it that correctly handle the
cross-compilation workflow without requiring host tools or other workarounds.

To make sure our build is correct, the upstream envoy lua tests are run in CI. See
[Upstream Tests](#upstream-tests) for details.

## Patches

There are several patches to upstream envoy that can be found in the `patches/envoy/` directory
(https://github.com/pomerium/envoy-custom/tree/main/patches/envoy). The majority of these patches
are small things to fix build issues, like adjustments to compiler flags and such. There are also
some changes to upstream test related code and adjustments to log messages in a few places. Any
patches whose names start with `fix-` are bugfixes that are intended to be contributed upstream
eventually. Patches with numeric prefixes are generally pomerium-specific or things that wouldn't
make sense to contribute upstream, like things needed for our downstream build process.

## Code Style

The code style is mostly identical to upstream, but there are some small changes to the
`.clang-format` config in envoy-custom.

Most of these changes are related to indentation and alignment. For example, the column limit of 100
is no longer strictly enforced by clang-format, as it is mostly just annoying and sometimes produces
strangely formatted and/or difficult to read code. The 100 column limit is still respected but long
lines are formatted by hand instead. Several other alignment and indentation rules are adjusted from
the defaults to make this easier, since the defaults can be quite aggressive.

Another important change is that single-line if statements and other blocks _must_ have brackets.
Trailing comment alignment is also enabled, which works similarly to gofmt.

## Compiler Options

- The SSH extension enables a few additional compiler warnings that are not enabled by default.
  These are:
  - `-Wimplicit-fallthrough` requires explicitly annotating case fallthrough in a switch statement
    with `[[fallthrough]]`.
  - `-Wimplicit-int-conversion` prevents most kinds of implicit integer conversion, which is a
    common source of hard-to-find bugs. Converting between integer types instead requires an
    explicit `static_cast`.
  - `-Wunsafe-buffer-usage` is a clang feature that helps prevent some classes of buffer overflow
    bugs. It more or less requires you to design a lot of your code around it, so it's an explicitly
    opt-in feature. It prevents using pointer arithmetic, prevents direct usage of `memcpy` and
    other unsafe C library functions, as well as several unsafe C++ functions. You can read more
    about this feature here: https://clang.llvm.org/docs/SafeBuffers.html
- The `-Wno-missing-designated-field-initializers` flag is enabled globally. The expected behavior
  of this warning (and of `Wmissing-field-initializers`, which we do enable) is the subject of much
  debate. This warning does not currently function in a reasonable way in C++.
- C++23 language features are enabled. Select C++26 extensions are also used, such as
  user-formattable static_assert messages.
- ASAN builds use `-O0` instead of `-O1`. This makes asan binaries run (a lot) slower, but makes
  them usable in a debugger.
- The default upstream host platform is called `clang_platform` which is an alias that automatically
  detects the host platform. This is not used in envoy-custom because it can cause issues with host
  detection and build output caching when using `--platform` during cross-compilation See
  [Cross-compiling](#cross-compiling) for more details (this is why it is recommended to always use
  `--host_platform`)

# 8. Dynamic Extensions

The dynamic extension system can be used to build and load optional out-of-tree extensions. It is
conceptually similar to upstream Envoy's dynamic modules. The two systems differ in terms of how the
extensions are built and how they interact with the main program.

## How It Works

There is no defined ABI other than the startup hook and shutdown hook. Extensions are able to
interact freely with the main program as if they were statically compiled in. The trade off, of
course, is no compatibility between versions. Extensions must be built for a specific version
(commit sha) of Envoy, and they can only be loaded for that exact version.

Extensions are defined using the `cc_dynamic_extension` bazel macro defined in
`bazel/dynamic_extension.bzl`. This macro accepts the standard srcs/hdrs/copts options, and also has
an option called `host_deps` in place of the usual `deps`. When the extension is linked into a
shared object, symbols needed by the extension that are from a library in `host_deps` are left
undefined. Then, when the extension is loaded into the main program at runtime, the undefined
symbols must be present in the dynamic symbol table of the main program so they can be resolved.

By default, `host_deps` includes `@envoy//envoy/server:instance_interface`, which covers most of the
envoy public api types, and `@envoy//source/common/common:logger_lib`. Common libraries used to
build extensions found in `@envoy//source/*` will need to be added to `host_deps` as needed.

The only [user-]defined symbols in the extension are those from the source files given by `srcs` in
`cc_dynamic_extension`, plus any protobuf apis given by `internal_api_deps`. This means the compiled
extensions can be very small.

## Metadata

Extensions can define metadata as `key=value` strings which are embedded into the `.dx_metadata` elf
section of the binary. The metadata section is read by the extension loader before actually loading
the extension. Extensions define an ID and license as follows:

```cpp
DYNAMIC_EXTENSION("example-extension");
DYNAMIC_EXTENSION_LICENSE("Apache-2.0");
```

They can also define their own metadata fields with the `DYNAMIC_EXTENSION_METADATA` macro if
desired. The id and license fields are the only "well-known" keys right now.

## Configuration

The extension loader itself is a bootstrap extension. Its configuration contains a list of paths to
extension files to load, and a map of optional configuration messages keyed by extension ID. Whether
an extension requires separate configuration or not is specific to that extension. For example:

```yaml
bootstrap_extensions:
  - name: envoy.bootstrap.dynamic_extension_loader
    typed_config:
      "@type": type.googleapis.com/pomerium.extensions.dynamic_extension_loader.Config
      paths:
        - /path/to/some_extension.so
      extension_configs:
        some.extension.id:
          "@type": type.googleapis.com/...
          foo: bar
```

## Admin endpoint

There is a basic admin endpoint at `/dynamic_extensions/status` which lists all loaded extensions
and their metadata, and also any extensions that may have failed to load along with the metadata and
the relevant error.

## `read-extension` CLI

To make developing and debugging extensions easier, there is a CLI tool called `read-extension`
which can print embedded extension metadata, list symbols, and check if an extension is compatible
with a specific envoy binary. This tool is also invoked in some of the integration tests for sanity
checking and to make failures more visible.

## Debug Info

Dynamic extensions do not use fission like the main envoy program does. When compiled in `dbg` mode,
all debug info will be included in the extension.

## ABI

### Startup Hook

The ABI defines a startup hook as the entrypoint for an extension. The startup hook can take one of
two forms:

```cpp
void dynamicExtensionInit(Envoy::Server::Instance& instance);
void dynamicExtensionInit(const google::protobuf::Message&, Envoy::Server::Instance& instance);
```

An extension can define one, both, or neither of these hooks. Only one will be called, depending on
whether the extension has a configuration message set in the extension loader's config.

### Shutdown Hook

There is also an optional shutdown hook which is called when the extension loader instance is
destroyed:

```cpp
void dynamicExtensionExit();
```

This hook is optional and will only be invoked if it is defined (and exported) by the extension.

The shutdown hook gives extensions a chance to perform any cleanup that would be complicated or
unsafe if using lifecycle callbacks. In particular, destroying a lifecycle callback handle (which
appears to be unsafe from within the callback itself, at least in some cases, despite comments in
the envoy source suggesting otherwise) should be done in the shutdown hook.
