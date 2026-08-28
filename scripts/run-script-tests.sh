#!/usr/bin/env bash
# Runs every scripts/*.test.main.kts suite in THIS repository.
#
# Self-locating: this runner tests the tree IT lives in, not the caller's cwd. The glob
# below is relative, so without the cd an absolute invocation from elsewhere — a review
# pod testing its own workspace — would silently enumerate and run whatever repo the
# caller happened to be standing in.
#
# The compiled-script cache is disabled because it keys on the top-level script file
# alone: an edit to an @file:Import-ed lib (scripts/lib/*.kts) would otherwise replay the
# stale compiled suite and report green without compiling the change.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
for t in scripts/*.test.main.kts; do
  echo "=== $t"
  if ! KOTLIN_MAIN_KTS_COMPILED_SCRIPTS_CACHE_DIR="" "$t"; then
    status=1
  fi
done
exit $status
