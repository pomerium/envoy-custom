#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: check_macos_tcmalloc_symbols.sh /path/to/envoy}"

if [[ ! -f "${binary}" ]]; then
  echo "envoy binary not found: ${binary}" >&2
  exit 1
fi

if ! /usr/bin/file "${binary}" | grep -q "Mach-O"; then
  echo "not a Mach-O binary: ${binary}" >&2
  exit 1
fi

if ! /usr/bin/nm -gU "${binary}" >/dev/null 2>&1; then
  echo "failed to inspect symbols in ${binary}" >&2
  exit 1
fi

bad_symbols="$(
  /usr/bin/nm -gU "${binary}" | /usr/bin/c++filt | \
    grep -E "tcmalloc::| operator (new|delete)( |\[)" || true
)"

if [[ -n "${bad_symbols}" ]]; then
  cat >&2 <<'EOF'
Darwin Envoy exports tcmalloc internal symbols.

When tcmalloc internals leak as globally-exported symbols on Darwin,
dyld's load-time fixup pass corrupts allocator state and the binary
crashes inside tcmalloc on startup or exit. These symbols must either
be absent or remain local in the Darwin binary.
EOF
  echo "${bad_symbols}" >&2
  exit 1
fi
