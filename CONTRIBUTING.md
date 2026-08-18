# Contributing to grith

Thank you for your interest in contributing to grith.

## Development Setup

```bash
# Prerequisites: Rust stable (1.80+), Node.js 20+
git clone https://github.com/grith-ai/grith.git && cd grith

cargo build                                    # Build all crates
cargo test --workspace                         # Run all tests
cargo clippy --workspace -- -D warnings        # Lint
cargo fmt -- --check                           # Format check
```

## Code Style

- **Rust:** `rustfmt` + `clippy` (pedantic). Run both before submitting.
- **TypeScript:** Prettier + ESLint (dashboard).
- **TOML:** `taplo` for formatting.

## Git Conventions

- **Branch naming:** `feat/`, `fix/`, `docs/`, `refactor/`, `test/`, `ci/`
- **Commit messages:** [Conventional Commits](https://www.conventionalcommits.org/) — `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `ci:`, `refactor:`
- **PRs:** All changes via PR, CI must pass, squash merge to main.

## Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Rust crates | `grith-{name}` | `grith-proxy` |
| Rust modules | `snake_case` | `path_match.rs` |
| Config keys | `snake_case` | `auto_deny_threshold` |
| Filter IDs | `kebab-case` | `ssh-key-access` |
| API routes | `kebab-case` | `/api/digest` |
| Env vars | `GRITH_UPPER_SNAKE` | `GRITH_LOG_LEVEL` |

## How contributions land

grith is developed in a private monorepo and exported to the public
repository per release, which is why the public history is squashed. Pull
requests are welcome on the public repository: they are reviewed on GitHub,
applied to the internal tree, and credited with Co-authored-by trailers and
in the CHANGELOG.

## Contributor License Agreement

Before a first pull request can be accepted, we ask contributors to sign the
[Contributor License Agreement](CLA.md). Signing is electronic: the CLA bot
prompts on your first PR, and you sign by posting the comment it asks for.

The short version: you keep the copyright to your contribution, you grant
Field Logic Ltd a licence broad enough to ship grith both under MPL-2.0 and
under commercial licence terms from one codebase, and you confirm the work is
yours to contribute. The public repository is licensed under MPL-2.0.
