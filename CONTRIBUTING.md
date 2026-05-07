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

## Licence

By contributing, you agree that your contributions will be licensed under MPL-2.0.
