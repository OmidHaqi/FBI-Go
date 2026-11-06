#!/bin/sh
set -eu
version=$1
arch=$2
bundle=$3
out=$4
case "$arch" in x86_64) deb_arch=amd64; rpm_arch=x86_64; elf_arch='x86-64' ;; aarch64) deb_arch=arm64; rpm_arch=aarch64; elf_arch='aarch64' ;; *) exit 1 ;; esac
mkdir -p "$out"
deb=$(find "$bundle/deb" -maxdepth 1 -type f -name '*.deb' -print -quit)
rpm=$(find "$bundle/rpm" -maxdepth 1 -type f -name '*.rpm' -print -quit)
appimage=$(find "$bundle/appimage" -maxdepth 1 -type f -name '*.AppImage' -print -quit)
test -n "$deb" && test -n "$rpm" && test -n "$appimage"
deb=$(realpath "$deb")
rpm=$(realpath "$rpm")
appimage=$(realpath "$appimage")
test "$(dpkg-deb -f "$deb" Architecture)" = "$deb_arch"
base=${version%%-*}
if [ "$version" != "$base" ]; then
  test "$(dpkg-deb -f "$deb" Version)" = "$base"
else
  test "$(dpkg-deb -f "$deb" Version)" = "$version"
fi
test "$(rpm -qp --qf '%{ARCH}' "$rpm")" = "$rpm_arch"
test "$(rpm -qp --qf '%{VERSION}' "$rpm")" = "$base"
if [ "$version" != "$base" ]; then
  test "$(rpm -qp --qf '%{RELEASE}' "$rpm")" = "0.${version#*-}"
else
  test "$(rpm -qp --qf '%{RELEASE}' "$rpm")" = 1
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
dpkg-deb -x "$deb" "$tmp/deb"
for program in fbi fbi-go-desktop; do
  test -x "$tmp/deb/usr/bin/$program"
  file "$tmp/deb/usr/bin/$program" | grep -q "$elf_arch"
done
test "$("$tmp/deb/usr/bin/fbi" version)" = "$version"
test -f "$tmp/deb/usr/share/applications/FBI-Go.desktop"
test -f "$tmp/deb/usr/share/icons/hicolor/512x512/apps/fbi-go-desktop.png"
mkdir -p "$tmp/rpm"
(cd "$tmp/rpm" && rpm2cpio "$rpm" | cpio -id --quiet)
for program in fbi fbi-go-desktop; do
  test -x "$tmp/rpm/usr/bin/$program"
  file "$tmp/rpm/usr/bin/$program" | grep -q "$elf_arch"
done
test "$("$tmp/rpm/usr/bin/fbi" version)" = "$version"
test -f "$tmp/rpm/usr/share/applications/FBI-Go.desktop"
test -f "$tmp/rpm/usr/share/icons/hicolor/512x512/apps/fbi-go-desktop.png"
file "$appimage" | grep -q "$elf_arch"
(cd "$tmp" && "$appimage" --appimage-extract >/dev/null)
for program in fbi fbi-go-desktop; do
  packaged=$(find "$tmp/squashfs-root" -type f -name "$program" -print -quit)
  test -n "$packaged"
  file "$packaged" | grep -q "$elf_arch"
done
if [ "$version" != "$base" ]; then
  dpkg-deb -R "$deb" "$tmp/deb-repack"
  sed -i "s/^Version: .*/Version: ${base}~${version#*-}/" "$tmp/deb-repack/DEBIAN/control"
  dpkg-deb --build --root-owner-group "$tmp/deb-repack" "$out/FBI-Go_${version}_linux_${arch}.deb" >/dev/null
  test "$(dpkg-deb -f "$out/FBI-Go_${version}_linux_${arch}.deb" Version)" = "${base}~${version#*-}"
else
  cp "$deb" "$out/FBI-Go_${version}_linux_${arch}.deb"
fi
for extension in deb rpm AppImage; do
  case "$extension" in deb) continue ;; rpm) source=$rpm ;; AppImage) source=$appimage ;; esac
  cp "$source" "$out/FBI-Go_${version}_linux_${arch}.${extension}"
done
