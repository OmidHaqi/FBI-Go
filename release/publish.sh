#!/bin/sh
set -eu
tag=$1
sha=$2
channel=$3
assets=$4
printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-dev\.[0-9]+\.[a-f0-9]{7,40})?$' || { echo "Invalid tag" >&2; exit 1; }
case "$sha" in *[!a-f0-9]*|'') echo "Invalid SHA" >&2; exit 1 ;; esac
test "${#sha}" -eq 40
test "$channel" = dev || test "$channel" = stable
if [ "$channel" = dev ]; then
  case "$tag" in *-dev.*) ;; *) echo "Tag/channel mismatch" >&2; exit 1 ;; esac
else
  case "$tag" in *-dev.*) echo "Tag/channel mismatch" >&2; exit 1 ;; esac
fi
test -f "$assets/SHA256SUMS.txt"
for arch in x86_64 aarch64; do
  for extension in deb rpm AppImage; do
    test -s "$assets/FBI-Go_${tag#v}_linux_${arch}.${extension}" || { echo "Incomplete architecture matrix" >&2; exit 1; }
  done
done
test "$(find "$assets" -maxdepth 1 -type f | wc -l)" -eq 7 || { echo "Unexpected release asset" >&2; exit 1; }
test "$(wc -l < "$assets/SHA256SUMS.txt")" -eq 6 || { echo "Incomplete checksum manifest" >&2; exit 1; }
(cd "$assets" && sha256sum -c SHA256SUMS.txt >/dev/null) || { echo "Checksum mismatch" >&2; exit 1; }
expected=$(git ls-remote --tags origin "refs/tags/$tag" | awk '{print $1}')
if [ -n "$expected" ] && [ "$expected" != "$sha" ]; then
  echo "Tag already belongs to another commit" >&2
  exit 1
fi
if gh release view "$tag" --json isDraft,targetCommitish >/dev/null 2>&1; then
  actual=$(gh release view "$tag" --json targetCommitish --jq .targetCommitish)
  test "$actual" = "$sha" || { echo "Release target mismatch" >&2; exit 1; }
  draft=$(gh release view "$tag" --json isDraft --jq .isDraft)
  test "$draft" = false || { echo "Existing draft needs operator review" >&2; exit 1; }
  for arch in x86_64 aarch64; do
    for extension in deb rpm AppImage; do
      gh release view "$tag" --json assets --jq '.assets[].name' | grep -Fxq "FBI-Go_${tag#v}_linux_${arch}.${extension}" || { echo "Existing release is missing an asset" >&2; exit 1; }
    done
  done
  gh release view "$tag" --json assets --jq '.assets[].name' | grep -Fxq SHA256SUMS.txt || { echo "Existing release is missing checksums" >&2; exit 1; }
  echo "Existing published release for the same commit; no mutation"
  exit 0
fi
notes=$(mktemp)
trap 'rm -f "$notes"' EXIT HUP INT TERM
printf 'Channel: %s\nSource commit: %s\nArchitectures: x86_64, aarch64\n\nInstall the package matching your architecture. See docs/install.md.\n\nHost routing activation remains UNSUPPORTED. This release provides read-only monitoring, planning and policy-file editing.\n\nVerify downloads against SHA256SUMS.txt.\n' "$channel" "$sha" > "$notes"
if [ "$channel" = dev ]; then
  gh release create "$tag" "$assets"/* --target "$sha" --title "FBI-Go ${tag#v} (Pre-release)" --notes-file "$notes" --generate-notes --draft --prerelease --latest=false
  gh release edit "$tag" --draft=false --prerelease=true --latest=false
else
  gh release create "$tag" "$assets"/* --target "$sha" --title "FBI-Go ${tag#v}" --notes-file "$notes" --generate-notes --draft --latest=false
  gh release edit "$tag" --draft=false --prerelease=false --latest=true
fi
