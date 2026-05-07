# Releasing grith

How to cut a new release of grith.

## Prerequisites

- Push access to `grith-ai/grith` on GitHub
- All CI checks passing on `main` (`cargo fmt`, `clippy`, tests, MSRV, dashboard, security audit)
- `CHANGELOG.md` updated with entries under `[Unreleased]`

## Version scheme

Pre-1.0: `0.MINOR.PATCH` (breaking changes bump MINOR, fixes bump PATCH).
Post-1.0: [Semantic Versioning](https://semver.org/).

The workspace version in `Cargo.toml` is the single source of truth — all crates inherit from `[workspace.package].version`.

## Release checklist

### 1. Prepare the changelog

Move entries from `[Unreleased]` into a new version heading:

```markdown
## [<version>] - YYYY-MM-DD

### Added
- ...
```

Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Group changes under `Added`, `Changed`, `Fixed`, `Removed`.

### 2. Bump the version

Update the workspace version in `Cargo.toml`:

```toml
[workspace.package]
version = "<version>"
```

All crates inherit this version automatically.

### 3. Commit the version bump

```bash
git add Cargo.toml CHANGELOG.md
git commit -m "chore: release v<version>"
```

### 4. Tag the release

```bash
git tag v<version>
git push origin main --tags
```

Pushing the `v*` tag triggers the [release workflow](#what-the-release-workflow-does).

### 5. Verify the release

1. Watch the [Actions tab](https://github.com/grith-ai/grith/actions/workflows/release.yml) — all 5 platform builds should pass.
2. Check the [Releases page](https://github.com/grith-ai/grith/releases) — the new release should appear with:
   - Auto-generated release notes (from conventional commits since last tag)
   - 10 assets: 5 archives + 5 `.sha256` checksum files
3. Smoke-test the installer:
   ```bash
   curl -fsSL https://grith.ai/install | sh -s -- --version <version>
   grith --version
   ```

### 6. Post-release

- Bump `Cargo.toml` to the next dev version (e.g. `<next-version>`) and commit:
  ```bash
  git commit -am "chore: begin v<next-version> development cycle"
  ```
- Update grith-docs if API surface changed (auto-generated types are checked in CI)
- Announce on relevant channels

## What the release workflow does

Defined in `.github/workflows/release.yml`. Triggered by pushing a `v*` tag.

### Build matrix

| Target | Runner | Build tool |
|--------|--------|------------|
| `x86_64-unknown-linux-musl` | ubuntu-latest | `cross` |
| `aarch64-unknown-linux-musl` | ubuntu-latest | `cross` |
| `aarch64-apple-darwin` | macos-latest | `cargo` |
| `x86_64-apple-darwin` | macos-latest | `cargo` |
| `x86_64-pc-windows-msvc` | windows-latest | `cargo` |

### Steps per target

1. Checkout + install Rust stable (with target)
2. Install `cross` (musl targets only)
3. Build dashboard (`npm ci && npm run build` in `dashboard/`)
4. `cargo build --release --target <target> -p grith-core`
5. Create archive: `.tar.gz` (Unix) or `.zip` (Windows)
6. Verify archive contains the binary
7. Generate SHA-256 checksum file
8. Upload artifact

### GitHub Release

After all builds pass, the `release` job:
1. Downloads all build artifacts
2. Creates a GitHub Release with auto-generated notes
3. Attaches all archives and checksum files

## Package-manager distribution (deferred from v1 launch)

Homebrew (`Formula/grith.rb`) and Scoop (`dist/scoop/grith.json`) manifests exist but contain **placeholder SHA-256 hashes**. These channels are not part of the initial v1 launch — the primary install path is the shell installer:

```bash
curl -fsSL https://grith.ai/install | sh
```

### Post-release hash update (when enabling Homebrew/Scoop)

After a GitHub Release is published, update the package manifests:

```bash
# Download the checksum files from the release
VERSION=0.1.0
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
              aarch64-apple-darwin x86_64-apple-darwin; do
  curl -sSL "https://github.com/grith-ai/grith/releases/download/v${VERSION}/grith-${VERSION}-${target}.tar.gz.sha256"
done

# Windows
curl -sSL "https://github.com/grith-ai/grith/releases/download/v${VERSION}/grith-${VERSION}-x86_64-pc-windows-msvc.zip.sha256"
```

Replace the `PLACEHOLDER_SHA256_*` values in `Formula/grith.rb` and `dist/scoop/grith.json` with the real hashes, then submit to the Homebrew tap / Scoop bucket.

## Local release builds

For testing the release build locally without CI:

```bash
# Build all targets (requires cross-compilation toolchains)
./scripts/build-release.sh

# Build a single target
./scripts/build-release.sh --target x86_64-unknown-linux-musl

# Quick local release build
make release
```

Output goes to `dist/release-artifacts/`.

## CI pipeline overview

| Workflow | Trigger | What it checks |
|----------|---------|----------------|
| **CI** (`.github/workflows/ci.yml`) | Push to `main`, PRs | `cargo fmt`, `clippy -D warnings`, `cargo test`, MSRV 1.80, dashboard type-check/lint/build/test, API type drift |
| **Security audit** (`.github/workflows/security-audit.yml`) | Weekly (Mon) + PRs | `cargo audit` (CVEs), `cargo deny check` (license compliance) |
| **Release** (`.github/workflows/release.yml`) | `v*` tags | Cross-platform builds, archives, checksums, GitHub Release |

## Hotfix releases

For urgent fixes on a released version:

```bash
git checkout v<version>
git checkout -b fix/critical-bug
# ... fix, commit ...
git checkout main
git merge fix/critical-bug
# Bump to patch version
# version = "<patch-version>" in Cargo.toml
git commit -am "chore: release v<patch-version>"
git tag v<patch-version>
git push origin main --tags
```

## Troubleshooting

**Build fails for a single target:**
The release workflow uses `fail-fast: false`, so other targets still build. Fix the failing target and re-tag (delete the old tag first):
```bash
git tag -d v<version>
git push origin :refs/tags/v<version>
# fix, commit, then re-tag
git tag v<version>
git push origin main --tags
```

**Checksum mismatch on install:**
Re-download the archive. If the issue persists, the release may have been tampered with — investigate before distributing.

**`cross` build fails (musl targets):**
Ensure Docker is available on the CI runner. `cross` uses Docker containers for musl cross-compilation. Locally, install cross with `cargo install cross --locked`.
