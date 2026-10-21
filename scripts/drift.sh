#!/usr/bin/env bash
# Dependency drift check: set up the newest versions of our tools, so the
# normal make targets can run against them. Used by .github/workflows/drift.yml.
#
# It never changes anything in the repo. It:
#   1. installs the newest release of every package in requirements.txt
#      (pins removed), into whatever Python $PYTHON points at;
#   2. downloads the newest Zircolite release into tools/zircolite-latest/,
#      checked against that release's SHA256SUMS file;
#   3. writes build/drift/versions.md: pinned, tested and newest released
#      version of each tool.
#
# Afterwards, run the make targets with ZIRCOLITE_DIR=tools/zircolite-latest
# (the workflow does this). If results change, a newer version changed them;
# pins are moved by hand after review.
#
# Usage: scripts/drift.sh            (PYTHON defaults to python3)

set -euo pipefail

PYTHON="${PYTHON:-python3}"
OUT=build/drift
mkdir -p "$OUT"

# --- 1. Newest Python packages ---------------------------------------------
# Drop comment lines and blank lines, then cut each line at the first version
# operator (==, >=, ...), which also drops any trailing comment.
grep -vE '^[[:space:]]*(#|$)' requirements.txt \
  | sed -E 's/[[:space:]]*[=<>~!].*//' > "$OUT/requirements-unpinned.txt"
echo "Installing newest versions of:"
cat "$OUT/requirements-unpinned.txt"
"$PYTHON" -m pip install --upgrade -r "$OUT/requirements-unpinned.txt"

# --- 2. Newest Zircolite -----------------------------------------------------
# Newest release tag of the form vX.Y.Z (git works without the GitHub API).
ZIRC_LATEST=$(git ls-remote --tags https://github.com/wagga40/Zircolite.git \
  | grep -oE 'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' | sed 's|refs/tags/v||' \
  | sort -V | tail -1)
ZIRC_PINNED=$(sed -nE 's/^ZIRCOLITE_VERSION[[:space:]]*:=[[:space:]]*//p' Makefile)

# The checksum for the linux-x64 build, from the release's own SHA256SUMS.
ZIRC_ZIP="Zircolite-${ZIRC_LATEST}-linux-x64.zip"
ZIRC_SHA=$(curl -fsSL "https://github.com/wagga40/Zircolite/releases/download/v${ZIRC_LATEST}/SHA256SUMS" \
  | awk -v f="$ZIRC_ZIP" '$2 == f {print $1}')
if [ -z "$ZIRC_SHA" ]; then
  echo "No $ZIRC_ZIP in the SHA256SUMS of Zircolite v$ZIRC_LATEST (release layout changed?)" >&2
  exit 1
fi

# Reuse the Makefile's download-and-verify recipe with the newest version.
rm -rf tools/zircolite-latest
make zircolite ZIRCOLITE_VERSION="$ZIRC_LATEST" ZIRCOLITE_SHA256="$ZIRC_SHA" \
  ZIRCOLITE_DIR=tools/zircolite-latest

# --- 3. Version table --------------------------------------------------------
"$PYTHON" - "$OUT/versions.md" "$ZIRC_PINNED" "$ZIRC_LATEST" <<'EOF'
import json, re, sys, urllib.request
from importlib.metadata import version

def newest_on_pypi(name):
    # pip installs the newest versions that fit together; a package held back
    # by another package's version limit shows up here as newer than installed.
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json") as r:
        return json.load(r)["info"]["version"]

out, zirc_pinned, zirc_latest = sys.argv[1:4]
rows = []
for line in open("requirements.txt"):
    m = re.match(r"\s*([A-Za-z0-9_.-]+)==([^\s#]+)", line)
    if m:
        name, pinned = m.groups()
        rows.append((name, pinned, version(name), newest_on_pypi(name)))
rows.append(("Zircolite", zirc_pinned, zirc_latest, zirc_latest))

with open(out, "w") as f:
    f.write("| Tool | Pinned | Tested here | Newest released | |\n|---|---|---|---|---|\n")
    for name, pinned, tested, newest in rows:
        notes = []
        if tested != pinned:
            notes.append("**newer**")
        if newest != tested:
            notes.append("held back by another package's version limit")
        f.write(f"| {name} | {pinned} | {tested} | {newest} | {', '.join(notes)} |\n")
print(open(out).read())
EOF
