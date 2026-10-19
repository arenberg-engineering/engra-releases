#!/usr/bin/env bash
# Release-asset allowlist for arenberg-engineering/engra-releases.
#
#   scripts/check-release-assets.sh <version> <file-or-name>...
#
# Passes only when the given assets are EXACTLY the Engra CLI distribution
# set for <version>:
#   - archives (tar.gz / zip);
#   - SBOMs (CycloneDX, SPDX);
#   - per-platform THIRD_PARTY_NOTICES;
#   - LICENSE.txt, TERMS.md, SHA256SUMS and signing-status.json.
# Provenance attestations live in GitHub's attestation store, not as files.
# It also scans every text asset that exists on disk for credentials and
# internal endpoints. Source code, scripts, configs and anything unexpected
# fail.
set -euo pipefail

VERSION="${1:?usage: check-release-assets.sh <version> <asset>...}"
shift
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo "::error::bad version $VERSION" >&2
  exit 1
}
V="${VERSION//./\\.}"
P="(macos-arm64|macos-x64|linux-x64|linux-arm64|windows-x64)"
allowed=(
  "^engra-$V-(macos-arm64|macos-x64|linux-x64|linux-arm64)\\.tar\\.gz$"
  "^engra-$V-windows-x64\\.zip$"
  "^engra-$V-$P\\.(cdx|spdx)\\.json$"
  "^THIRD_PARTY_NOTICES-$P\\.txt$"
  "^(LICENSE\\.txt|TERMS\\.md|SHA256SUMS|signing-status\\.json)$"
)
expected=$((5 + 10 + 5 + 4))

# Credentials and internal endpoints that must never ship.
secret_re='(-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[abprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9A-Za-z]{10,}|[a-z0-9-]+\.run\.app|[a-z0-9.-]+\.internal\b|metadata\.google\.internal|engra-prod|127\.0\.0\.1:[0-9]{2,5}/)'

bad=0
seen=()
for item in "$@"; do
  name="$(basename "$item")"
  ok=0
  for re in "${allowed[@]}"; do
    if [[ "$name" =~ $re ]]; then
      ok=1
      break
    fi
  done
  if ((ok == 0)); then
    echo "::error::not a distribution asset: $name"
    bad=1
    continue
  fi
  for prior in "${seen[@]+"${seen[@]}"}"; do
    [[ "$prior" == "$name" ]] && {
      echo "::error::duplicate asset: $name"
      bad=1
    }
  done
  seen+=("$name")
  if [[ -f "$item" && "$name" =~ \.(json|txt|md)$|^SHA256SUMS$ ]]; then
    if grep -EIq "$secret_re" "$item"; then
      echo "::error::$name contains a credential-like string or an internal endpoint"
      bad=1
    fi
  fi
done
if ((${#seen[@]} != expected)); then
  echo "::error::expected $expected assets for $VERSION, got ${#seen[@]}"
  bad=1
fi
((bad == 0)) && echo "[assets] OK: ${#seen[@]} distribution assets for $VERSION"
exit "$bad"
