# Linux releases

The release workflows build one native artifact matrix on GitHub-hosted x86_64 and aarch64 Linux runners. Each architecture produces RPM, DEB, and AppImage packages containing the Tauri desktop executable and a same-architecture Go `fbi` CLI. A release also contains `SHA256SUMS.txt`. CI validates source, frontend, Rust, package metadata, ELF architecture, and included binaries before publication. These workflows do not run privileged namespace tests or authorize production host routing.

## Channels

- A push to `develop` starts a development pre-release after the full package matrix succeeds. Tags use `v2.0.0-dev.<run>.<source-sha-prefix>` until the next stable version advances. A failed build publishes nothing.
- A merged pull request from this repository's `develop` branch into `main` starts a stable release from the exact merge commit. Stable versions start at `2.0.0` and increment the patch number for that major/minor line. Update `release/version-policy.json` deliberately to start a new minor or major line.
- Other pull requests run validation, not publication. Publishing uses the workflow token with `contents: write`; build jobs retain read-only repository access.

Protect `main` with reviewed pull requests, the CI check, and no force pushes or direct pushes. Protect `develop` from force pushes and require CI before merge. Keep the repository's Actions permission policy narrow and allow the release workflow to create releases with its scoped token. These are repository settings for maintainers; the source tree cannot enforce them by itself.

Development releases use SemVer in the source, CLI, UI, and release tag. Linux packages need distribution-specific ordering: the RPM has base Version with Release `0.dev.<run>.<sha>`, and the DEB Version is `<base>~dev.<run>.<sha>`. Both sort before the corresponding stable release. Tauri uses the base SemVer for its Linux bundler because RPM rejects a hyphen in the Version field. The AppImage asset name carries the full development release version. This packaging metadata difference does not enable host routing.

The publisher checks the complete six-package matrix and its checksums before creating a draft release. A rerun after a completed publication is read-only. An interrupted draft is left for maintainer review; the workflow does not overwrite or delete existing release assets automatically.

## Building locally

After installing the [Tauri Linux prerequisites](https://v2.tauri.app/start/prerequisites/):

```sh
cd desktop
npm ci
npm run tauri build -- --bundles deb,rpm,appimage
```

This builds the current architecture only. Linux package artifacts are under `desktop/src-tauri/target/release/bundle/`. The release workflow uses an arm64 runner for aarch64; it does not label an x86_64 cross-build as an arm64 package.

Before installing a downloaded artifact, verify its SHA-256 checksum with `sha256sum -c SHA256SUMS.txt` in a directory containing all listed assets. AppImage may need `chmod +x` before launch. The desktop requires a separately started read-only daemon in the same user's session. No package installs a privileged service.

## Release safety

The published UI supports discovery, monitoring, planning, and the current user's policy-file edits. `PLAN_ONLY` is not active routing. `HOST_APPLY` remains unsupported. Do not use release artifacts as a substitute for isolated routing tests or host-specific safety review. See [operator safety](safety.md) and [the UI backend contract](ui-backend-contract.md).
