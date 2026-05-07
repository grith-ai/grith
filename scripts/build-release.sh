#!/usr/bin/env bash
# build-release.sh — Cross-platform release build script for grith
#
# Builds optimized release binaries for all supported targets, strips debug
# symbols, generates SHA-256 checksums, and creates compressed archives.
#
# Usage:
#   ./scripts/build-release.sh                      # Build all release targets
#   ./scripts/build-release.sh --target <triple>   # Build a single release target
#   ./scripts/build-release.sh --host-target       # Build the best available local dist target
#   ./scripts/build-release.sh --print-host-target # Print the best available local dist target
#   ./scripts/build-release.sh --print-canonical-host-target # Print the canonical release target for this platform
#   ./scripts/build-release.sh --help                # Show help
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"
RELEASE_DIR="${DIST_DIR}/release-artifacts"

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------
ALL_TARGETS=(
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-musl"
    "x86_64-pc-windows-msvc"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { printf "\033[1;34m[info]\033[0m  %s\n" "$*"; }
ok()    { printf "\033[1;32m[ok]\033[0m    %s\n" "$*"; }
warn()  { printf "\033[1;33m[warn]\033[0m  %s\n" "$*"; }
err()   { printf "\033[1;31m[error]\033[0m %s\n" "$*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Cross-platform release build script for grith.

Options:
  --target <triple>  Build only the specified target triple.
                     Supported targets:
$(printf '                       - %s\n' "${ALL_TARGETS[@]}")
  --host-target      Build only the best available local dist target.
                     Linux prefers the musl release target, but falls back to the
                     native host target when cross is unavailable.
  --print-host-target
                     Print the best available local dist target and exit.
  --print-canonical-host-target
                     Print the canonical release target for this platform and exit.
  --help             Show this help message and exit.

When no --target is given, all supported targets are built.

Output is placed in dist/release-artifacts/ with the layout:
  dist/release-artifacts/grith-<version>-<target>[.exe]         Versioned binary (for inspection)
  dist/release-artifacts/grith-<version>-<target>.tar.gz        Archive containing "grith" (Unix)
  dist/release-artifacts/grith-<version>-<target>.zip           Archive containing "grith.exe" (Windows)
  dist/release-artifacts/grith-<version>-<target>.tar.gz.sha256 SHA-256 checksum of archive
EOF
}

get_version() {
    # Extract version from workspace Cargo.toml
    local version
    version=$(grep -m1 '^version' "${PROJECT_ROOT}/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
    if [[ -z "${version}" ]]; then
        err "Could not determine version from Cargo.toml"
        exit 1
    fi
    printf '%s' "${version}"
}

is_windows_target() {
    [[ "$1" == *"windows"* ]]
}

is_unix_target() {
    ! is_windows_target "$1"
}

is_musl_target() {
    [[ "$1" == *"musl"* ]]
}

detect_canonical_host_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "${os}" in
        Linux)
            case "${arch}" in
                x86_64) printf 'x86_64-unknown-linux-musl' ;;
                aarch64|arm64) printf 'aarch64-unknown-linux-musl' ;;
                *)
                    err "Unsupported Linux architecture: ${arch}"
                    return 1
                    ;;
            esac
            ;;
        Darwin)
            case "${arch}" in
                x86_64) printf 'x86_64-apple-darwin' ;;
                aarch64|arm64) printf 'aarch64-apple-darwin' ;;
                *)
                    err "Unsupported macOS architecture: ${arch}"
                    return 1
                    ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            case "${arch}" in
                x86_64|amd64) printf 'x86_64-pc-windows-msvc' ;;
                *)
                    err "Unsupported Windows architecture: ${arch}"
                    return 1
                    ;;
            esac
            ;;
        *)
            err "Unsupported operating system: ${os}"
            return 1
            ;;
    esac
}

detect_native_host_target() {
    local host
    host="$(rustc -vV | awk '/^host:/ {print $2}')"
    if [[ -z "${host}" ]]; then
        err "Could not determine native host target from rustc"
        return 1
    fi
    printf '%s' "${host}"
}

resolve_local_host_target() {
    local canonical native
    canonical="$(detect_canonical_host_target)" || return 1

    if is_musl_target "${canonical}"; then
        native="$(detect_native_host_target)" || return 1
        if [[ "${native}" != "${canonical}" ]] && ! command -v cross >/dev/null 2>&1; then
            if [[ "${1:-warn}" == "warn" ]]; then
                printf "\033[1;33m[warn]\033[0m  cross not found; falling back to native host target %s for local dist.\n" "${native}" >&2
                printf "\033[1;33m[warn]\033[0m  Use dist-all or CI to build canonical Linux musl release assets.\n" >&2
            fi
            printf '%s' "${native}"
            return 0
        fi
    fi

    printf '%s' "${canonical}"
}

# Returns the build command: "cross" for musl targets, "cargo" otherwise.
build_cmd() {
    local target="$1"
    if is_musl_target "${target}"; then
        local native
        native="$(detect_native_host_target)" || return 1
        if [[ "${target}" == "${native}" ]]; then
            printf 'cargo'
        elif command -v cross >/dev/null 2>&1; then
            printf 'cross'
        else
            err "cross is required for musl targets but not found."
            err "Install with: cargo install cross --locked"
            err "Or build the best available local dist target with: $0 --host-target"
            return 1
        fi
    else
        printf 'cargo'
    fi
}

binary_name() {
    local version="$1" target="$2"
    if is_windows_target "${target}"; then
        printf 'grith-%s-%s.exe' "${version}" "${target}"
    else
        printf 'grith-%s-%s' "${version}" "${target}"
    fi
}

# ---------------------------------------------------------------------------
# Build one target
# ---------------------------------------------------------------------------
build_target() {
    local target="$1"
    local version="$2"
    local bin_name
    bin_name="$(binary_name "${version}" "${target}")"

    info "Building grith v${version} for ${target} ..."

    # Use cross for musl targets (matches release.yml CI workflow), cargo otherwise
    local cmd
    cmd="$(build_cmd "${target}")" || return 1
    info "Using ${cmd} for ${target}"
    "${cmd}" build --release --target "${target}" -p grith-core

    # Locate the compiled binary
    local src_bin="${PROJECT_ROOT}/target/${target}/release/grith"
    if is_windows_target "${target}"; then
        src_bin="${src_bin}.exe"
    fi

    if [[ ! -f "${src_bin}" ]]; then
        err "Binary not found at ${src_bin}"
        return 1
    fi

    # Copy to dist with versioned name (for local inspection)
    local dest_bin="${RELEASE_DIR}/${bin_name}"
    cp "${src_bin}" "${dest_bin}"

    # Strip debug symbols
    if is_unix_target "${target}"; then
        if command -v strip >/dev/null 2>&1; then
            strip "${dest_bin}" 2>/dev/null || warn "strip failed for ${target} (cross-compilation target may need target-specific strip)"
        else
            warn "strip not found; skipping symbol stripping for ${target}"
        fi
    fi

    # Create compressed archive containing just "grith" / "grith.exe"
    # (matches release.yml and install.sh conventions)
    local archive_name
    if is_windows_target "${target}"; then
        archive_name="grith-${version}-${target}.zip"
        if command -v zip >/dev/null 2>&1; then
            (cd "${RELEASE_DIR}" && cp "${bin_name}" grith.exe && zip -q "${archive_name}" grith.exe && rm grith.exe)
        else
            warn "zip not found; skipping archive for ${target}"
        fi
    else
        archive_name="grith-${version}-${target}.tar.gz"
        (cd "${RELEASE_DIR}" && cp "${bin_name}" grith && tar czf "${archive_name}" grith && rm grith)
    fi

    # Generate SHA-256 checksum for the archive
    local checksum_file="${RELEASE_DIR}/${archive_name}.sha256"
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "${RELEASE_DIR}" && sha256sum "${archive_name}") > "${checksum_file}"
    elif command -v shasum >/dev/null 2>&1; then
        (cd "${RELEASE_DIR}" && shasum -a 256 "${archive_name}") > "${checksum_file}"
    else
        err "Neither sha256sum nor shasum found; cannot generate checksum"
        return 1
    fi

    ok "Built ${bin_name}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local selected_targets=()
    local mode="all"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                usage
                exit 0
                ;;
            --host-target)
                if [[ "${mode}" != "all" || ${#selected_targets[@]} -gt 0 ]]; then
                    err "--host-target cannot be combined with other target selection flags"
                    exit 1
                fi
                mode="host"
                shift
                ;;
            --print-host-target)
                if [[ "${mode}" != "all" || ${#selected_targets[@]} -gt 0 ]]; then
                    err "--print-host-target cannot be combined with other target selection flags"
                    exit 1
                fi
                resolve_local_host_target quiet
                exit 0
                ;;
            --print-canonical-host-target)
                if [[ "${mode}" != "all" || ${#selected_targets[@]} -gt 0 ]]; then
                    err "--print-canonical-host-target cannot be combined with other target selection flags"
                    exit 1
                fi
                detect_canonical_host_target
                exit 0
                ;;
            --target)
                if [[ $# -lt 2 ]]; then
                    err "--target requires a value"
                    usage
                    exit 1
                fi
                if [[ "${mode}" != "all" ]]; then
                    err "--target cannot be combined with --host-target"
                    exit 1
                fi
                local valid=false
                for t in "${ALL_TARGETS[@]}"; do
                    if [[ "$2" == "${t}" ]]; then
                        valid=true
                        break
                    fi
                done
                if [[ "${valid}" != "true" ]]; then
                    err "Unsupported target: $2"
                    printf "Supported targets:\n"
                    printf "  - %s\n" "${ALL_TARGETS[@]}"
                    exit 1
                fi
                selected_targets+=("$2")
                shift 2
                ;;
            *)
                err "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    if [[ "${mode}" == "host" ]]; then
        selected_targets=("$(resolve_local_host_target warn)")
    elif [[ ${#selected_targets[@]} -eq 0 ]]; then
        selected_targets=("${ALL_TARGETS[@]}")
    fi

    local version
    version="$(get_version)"

    info "grith release build v${version}"
    info "Targets: ${selected_targets[*]}"

    # Prepare release artifact directory (leave tracked dist files intact)
    rm -rf "${RELEASE_DIR}"
    mkdir -p "${RELEASE_DIR}"

    # Build each target
    local success=0
    local fail=0
    local failed_targets=()

    for target in "${selected_targets[@]}"; do
        if build_target "${target}" "${version}"; then
            ((success++)) || true
        else
            ((fail++)) || true
            failed_targets+=("${target}")
        fi
    done

    # Summary
    printf "\n"
    info "============================================"
    info "  Release Build Summary"
    info "============================================"
    info "  Version:    ${version}"
    info "  Output:     ${RELEASE_DIR}/"
    info "  Succeeded:  ${success}"
    if [[ ${fail} -gt 0 ]]; then
        warn "  Failed:     ${fail}"
        for ft in "${failed_targets[@]}"; do
            warn "    - ${ft}"
        done
    fi
    info "============================================"

    printf "\nArtifacts:\n"
    ls -lh "${RELEASE_DIR}/" 2>/dev/null || true

    if [[ ${fail} -gt 0 ]]; then
        exit 1
    fi

    ok "All builds completed successfully."
}

main "$@"
