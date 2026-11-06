#!/usr/bin/env python3
"""Resolve and apply one release version without changing Git tags."""
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STABLE = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-dev\.[0-9]+\.[a-f0-9]{7,40})?$")


def linux_versions(version: str) -> tuple[str, str, str]:
    """Return Tauri/RPM base, RPM release, and installable DEB version."""
    if not VERSION.fullmatch(version):
        raise ValueError("invalid release version")
    if "-" not in version:
        return version, "1", version
    base, suffix = version.split("-", 1)
    return base, "0." + suffix, base + "~" + suffix


def next_stable(tags: list[str], major: int, minor: int) -> str:
    versions = [tuple(map(int, match.groups())) for tag in tags if (match := STABLE.fullmatch(tag))]
    latest = max(versions, default=None)
    if latest is not None and (major, minor) < latest[:2]:
        raise ValueError("version policy would downgrade an existing stable release")
    if latest is None or (major, minor) > latest[:2]:
        return f"{major}.{minor}.0"
    return f"{major}.{minor}.{latest[2] + 1}"


def resolve(channel: str, run_number: int, sha: str) -> str:
    policy = json.loads((ROOT / "release/version-policy.json").read_text())
    tags = subprocess.check_output(["git", "tag", "--list"], cwd=ROOT, text=True).splitlines()
    if channel == "stable" and sha:
        for tag in tags:
            if STABLE.fullmatch(tag):
                target = subprocess.check_output(["git", "rev-list", "-n1", tag], cwd=ROOT, text=True).strip()
                if target == sha:
                    return tag[1:]
    if channel == "dev" and run_number > 0 and re.fullmatch(r"[a-f0-9]{40}", sha):
        suffix = f"-dev.{run_number}.{sha[:7]}"
        for tag in tags:
            if tag.startswith("v") and tag.endswith(suffix):
                return tag[1:]
    stable = next_stable(tags, policy["major"], policy["minor"])
    if channel == "stable":
        return stable
    if run_number <= 0 or not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise ValueError("dev release requires a positive run number and full commit SHA")
    return f"{stable}-dev.{run_number}.{sha[:7]}"


def apply(version: str) -> None:
    bundle_version, rpm_release, _ = linux_versions(version)
    desktop = ROOT / "desktop"
    for name in ("package.json", "src-tauri/tauri.conf.json"):
        path = desktop / name
        data = json.loads(path.read_text())
        if name.endswith("tauri.conf.json"):
            data["version"] = bundle_version
            data.setdefault("bundle", {}).setdefault("linux", {}).setdefault("rpm", {})["release"] = rpm_release
        else:
            data["version"] = version
        path.write_text(json.dumps(data, indent=2) + "\n")
    lock = desktop / "package-lock.json"
    data = json.loads(lock.read_text())
    data["version"] = version
    data["packages"][""]["version"] = version
    lock.write_text(json.dumps(data, indent=2) + "\n")
    cargo = desktop / "src-tauri/Cargo.toml"
    content, count = re.subn(r'(?m)^version = "[^"]+"', f'version = "{version}"', cargo.read_text(), count=1)
    if count != 1:
        raise ValueError("Cargo package version missing")
    cargo.write_text(content)
    cargo_lock = desktop / "src-tauri/Cargo.lock"
    content, count = re.subn(r'(?m)(\[\[package\]\]\nname = "fbi-go-desktop"\nversion = ")[^"]+("\n)', rf'\g<1>{version}\2', cargo_lock.read_text(), count=1)
    if count != 1:
        raise ValueError("Cargo lock package version missing")
    cargo_lock.write_text(content)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("resolve", "apply"))
    parser.add_argument("--channel", choices=("dev", "stable"))
    parser.add_argument("--run-number", type=int, default=0)
    parser.add_argument("--sha", default="")
    parser.add_argument("--version")
    args = parser.parse_args()
    if args.command == "resolve":
        if not args.channel:
            parser.error("--channel required")
        print(resolve(args.channel, args.run_number, args.sha))
    else:
        if not args.version:
            parser.error("--version required")
        apply(args.version)


if __name__ == "__main__":
    main()
