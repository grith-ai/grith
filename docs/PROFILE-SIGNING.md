# Profile Signing Ceremony

This document describes the offline signing workflow for remote profile overlay manifests.

## Key Generation

Generate a dedicated Ed25519 keypair for profile manifest signing. This keypair is separate from the license-signing key.

```bash
# Generate 32-byte random seed.
openssl rand -hex 32 > profile-signing.key

# Derive the public key (the tool prints `Public key (hex): ...`).
cargo run -p grith-core --bin sign-profiles -- \
  --input config/supervisor/profiles.remote.toml \
  --output /dev/null \
  --version 0 \
  --key-file profile-signing.key
```

Compile release builds with the derived verifier key:

```bash
GRITH_PROFILE_PUBLIC_KEY_HEX="<public-key-hex>" cargo build --release -p grith-core --bin grith
```

Without `GRITH_PROFILE_PUBLIC_KEY_HEX`, local builds fall back to a bootstrap verifier key. That fallback is for local development only and should not be used for release artifacts that are expected to accept production-signed manifests.

## Key Storage

- **Private key**: Offline only. Never on the API server. Never in CI secrets. Store in a hardware security module or encrypted offline media.
- **Public key**: Compiled into release binaries via `GRITH_PROFILE_PUBLIC_KEY_HEX`.

## Signing Workflow

1. **Capture drift**: Run `grith exec --trace-syscalls-jsonl /tmp/trace.jsonl -- <tool> <args>` and then `grith profile audit --profile <name> --trace /tmp/trace.jsonl`.

2. **Review findings**: Check the "Remote Overlay Candidates" section of the audit output.

3. **Update source**: Edit `config/supervisor/profiles.remote.toml` with reviewed entries.

4. **Validate**: CI runs automatically on PRs touching the file.

5. **Sign**: On a secure offline machine:
   ```bash
   cargo run -p grith-core --bin sign-profiles -- \
     --input config/supervisor/profiles.remote.toml \
     --output dist/profiles.latest.json \
     --version <next_version> \
     --key-file /path/to/profile-signing.key
   ```

6. **Verify**: The signing tool validates schema, profile names, and entry constraints before signing.

7. **Upload**: Deploy `dist/profiles.latest.json` to `${API_BASE_URL}/v1/profiles/latest`.

## Review Checklist

Before signing a new manifest version:

- [ ] All new entries have been reviewed by a maintainer.
- [ ] No entries use wildcards, schemes, ports, or whitespace in destinations.
- [ ] No destinations are public-suffix-level or otherwise broad suffix matches (`com`, `co.uk`, etc.).
- [ ] No commands contain path separators or arguments.
- [ ] `routine_paths` stay in tool-scoped `${HOME}` subtrees, project subpaths, or tool-prefixed `/tmp` paths.
- [ ] `readonly_paths` are exact paths only. `readonly_path_patterns` use a single-segment `*` wildcard under `${HOME}` or `${PROJECT_DIR}`.
- [ ] All referenced profile names exist in the bundled `profiles.toml`.
- [ ] The `profiles_version` is strictly greater than the previous signed version.
- [ ] The `min_grith_version` is correct for the entries being added.
- [ ] The `changelog` accurately describes what changed.

## Anti-Rollback

The `profiles_version` field is monotonically increasing. Clients store the highest accepted version and reject any manifest with a version less than or equal to the stored value.

## CI Integration

- `.github/workflows/profile-remote-validate.yml` validates the actual `profiles.remote.toml` file through the signing path on PRs.
- `.github/workflows/profile-audit.yml` runs scheduled or manual audit captures.
- CI does not hold the signing key and does not publish signed manifests.
