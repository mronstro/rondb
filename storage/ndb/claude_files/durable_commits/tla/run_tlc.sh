#!/bin/sh
# RONDB-1150 X3.4: check the model of durable commits with TLC, one run per
# configuration (all MC_*.cfg, or the ones given), and print each verdict
# next to the one expected in the configuration's header (README.md).
#
#   TLA2TOOLS    tla2tools.jar (default: tla2tools.jar beside this script)
#   TLC_OUT      logs and TLC's state files (default: /tmp/durable_commits_tlc)
#   TLC_WORKERS  TLC worker threads (default: auto)
set -u
here=$(cd "$(dirname "$0")" && pwd)
jar=${TLA2TOOLS:-$here/tla2tools.jar}
out=${TLC_OUT:-/tmp/durable_commits_tlc}
workers=${TLC_WORKERS:-auto}

if [ ! -f "$jar" ]; then
  echo "No $jar. Download it with:" >&2
  echo "  curl -L -o $here/tla2tools.jar" \
       "https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar" >&2
  exit 1
fi
mkdir -p "$out"
cd "$here" || exit 1

# Parse and check the modules first
java -cp "$jar" tla2sany.SANY MC.tla > "$out/sany.log" 2>&1
if grep -qi "error" "$out/sany.log"; then
  cat "$out/sany.log"
  exit 1
fi

if [ $# -eq 0 ]; then
  set -- MC_*.cfg
fi
for cfg in "$@"; do
  name=$(basename "$cfg" .cfg)
  expected=$(grep '^\\\*' "$cfg" | sed 's/^\\\* *//' | tr '\n' ' ' |
             sed -n 's/.*Expected: \([^.]*\)\..*/\1/p')
  java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "$workers" -deadlock \
       -metadir "$out/$name" -config "$cfg" MC.tla > "$out/$name.log" 2>&1
  verdict=$(grep -E "No error has been found|is violated|^Error:" \
                 "$out/$name.log" | head -1)
  echo "$name"
  echo "  expected: $expected"
  echo "  TLC:      ${verdict:-no verdict, see $out/$name.log}"
done
