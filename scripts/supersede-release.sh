#!/usr/bin/env bash
# Mark an old Engra CLI release as superseded (OWNER STEP, after publishing).
#
#   scripts/supersede-release.sh v0.1.0 v0.2.0          # dry run: shows the change
#   scripts/supersede-release.sh v0.1.0 v0.2.0 --apply  # edits the old release
#
# Refuses unless <new> is published, is not a draft or pre-release, and is the
# repository's Latest release. It never deletes anything. It sets <old> to
# non-latest and puts a "Superseded by <new>" banner at the top of its notes.
# Running it twice is safe: the banner is added only once.
set -euo pipefail

OLD="${1:?usage: supersede-release.sh <old-tag> <new-tag> [--apply]}"
NEW="${2:?usage: supersede-release.sh <old-tag> <new-tag> [--apply]}"
APPLY="${3:-}"
REPO="${REPO:-arenberg-engineering/engra-releases}"
for t in "$OLD" "$NEW"; do
  [[ "$t" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
    echo "bad tag: $t" >&2
    exit 2
  }
done

new_state="$(gh release view "$NEW" --repo "$REPO" --json isDraft,isPrerelease,tagName -q '"\(.isDraft) \(.isPrerelease)"')"
[[ "$new_state" == "false false" ]] || {
  echo "refusing: $NEW is not a published, non-pre-release release ($new_state)" >&2
  exit 1
}
latest="$(gh api "repos/$REPO/releases/latest" -q .tag_name)"
[[ "$latest" == "$NEW" ]] || {
  echo "refusing: Latest is $latest, not $NEW" >&2
  exit 1
}
gh release view "$OLD" --repo "$REPO" --json tagName >/dev/null

detail=""
if [[ "$OLD" == "v0.1.0" ]]; then
  detail=" It reports version 0.0.1, ships for Apple silicon only and is not notarized."
fi
banner="> **Superseded by [$NEW](https://github.com/$REPO/releases/tag/$NEW).** This release is kept for reference only.$detail Upgrade with \`brew upgrade engra\` or install $NEW."
body="$(gh release view "$OLD" --repo "$REPO" --json body -q .body)"
if [[ "$body" == *"Superseded by ["* ]]; then
  echo "$OLD already carries a superseded banner; only the latest flag will be set"
  new_body="$body"
else
  new_body="$(printf '%s\n\n%s\n' "$banner" "$body")"
fi

echo "--- $OLD notes after the change ---"
printf '%s\n' "$new_body" | head -20
echo "-----------------------------------"
if [[ "$APPLY" != "--apply" ]]; then
  echo "dry run: re-run with --apply to edit $OLD in $REPO"
  exit 0
fi
notes="$(mktemp)"
printf '%s\n' "$new_body" >"$notes"
gh release edit "$OLD" --repo "$REPO" --latest=false --notes-file "$notes"
rm -f "$notes"
[[ "$(gh api "repos/$REPO/releases/latest" -q .tag_name)" == "$NEW" ]] || {
  echo "warning: Latest is no longer $NEW" >&2
  exit 1
}
echo "$OLD marked superseded by $NEW (not deleted); Latest is $NEW"
