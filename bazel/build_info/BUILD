load("@aspect_bazel_lib//lib:jq.bzl", "jq")

_convert_workspace_status = """
while IFS=$$'\n' read -r line; do
  KEY="$$(cut -d ' ' -f 1 <<<$$line)"
  VALUE="$$(cut -d ' ' -f 2- <<<$$line)"
  echo "{'$$KEY':'$$VALUE'}" | tr "'" '\"' >> $@
done < %s
"""

genrule(
    name = "stable_status_input",
    outs = ["_stable-status-input.txt"],
    cmd = _convert_workspace_status % "bazel-out/stable-status.txt",
    stamp = 1,
    tags = ["no-remote-exec"],
    visibility = ["//visibility:private"],
)

genrule(
    name = "volatile_status_input",
    outs = ["_volatile-status-input.txt"],
    cmd = _convert_workspace_status % "bazel-out/volatile-status.txt",
    stamp = 1,
    tags = ["no-remote-exec"],
    visibility = ["//visibility:private"],
)

jq(
    name = "stable_status",
    srcs = [":stable_status_input"],
    out = "stable_status.json",
    args = ["--slurp"],
    # merges json objects listed on each line into one single json object
    filter = "[.[]] | add",
    visibility = ["//visibility:public"],
)

jq(
    name = "volatile_status",
    srcs = [":volatile_status_input"],
    out = "volatile_status.json",
    args = ["--slurp"],
    filter = "[.[]] | add",
    visibility = ["//visibility:public"],
)

jq(
    name = "combined_status",
    srcs = [
        ":stable_status",
        ":volatile_status",
    ],
    out = "combined_status.json",
    args = ["--slurp"],
    filter = "[.[]] | add",
    visibility = ["//visibility:public"],
)
