#!/usr/bin/env sh
# install.sh — Installer for grith (Zero Trust for AI Agents)
#
# Usage:
#   curl -fsSL https://grith.ai/install | sh
#   curl -fsSL https://grith.ai/install | sh -s -- --version <version>
#   curl -fsSL https://grith.ai/install | sh -s -- --global
#
# Options:
#   --version <ver>  Install a specific version (default: latest)
#   --global         Install to /usr/local/bin instead of ~/.local/bin
#   --help           Show this help message
#
# Supported platforms:
#   - Linux x86_64  (static musl binary)
#   - Linux aarch64 (static musl binary)
#   - macOS x86_64  (Intel)
#   - macOS aarch64 (Apple Silicon)
#
# Windows is not supported by this installer. Use the MSI package or
# download the binary manually from GitHub Releases.
#
set -eu

REPO="grith-ai/grith"
BINARY_NAME="grith"
INSTALL_DIR="${HOME}/.local/bin"
VERSION=""
GLOBAL_INSTALL=false
# Test seams for local installer validation:
# - GRITH_RELEASE_BASE_URL overrides the release asset base URL.
# - GRITH_INSTALL_FORCE_TARGET bypasses platform detection when set.

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Log helpers write to stderr so functions like `resolve_version` that
# emit their data result on stdout don't get their captured value polluted
# by progress messages. Without this, `VERSION="$(resolve_version)"` ends
# up capturing both the "Fetching latest version..." info line and the
# version string itself, breaking the download URL.
info()  { printf "\033[1;34m[info]\033[0m  %s\n" "$*" >&2; }
ok()    { printf "\033[1;32m[ok]\033[0m    %s\n" "$*" >&2; }
warn()  { printf "\033[1;33m[warn]\033[0m  %s\n" "$*" >&2; }
err()   { printf "\033[1;31m[error]\033[0m %s\n" "$*" >&2; }

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "Required command not found: $1"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
detect_platform() {
    if [ -n "${GRITH_INSTALL_FORCE_TARGET:-}" ]; then
        printf '%s' "${GRITH_INSTALL_FORCE_TARGET}"
        return
    fi

    local os arch target

    os="$(uname -s)"
    arch="$(uname -m)"

    case "${os}" in
        Linux)
            case "${arch}" in
                x86_64)  target="x86_64-unknown-linux-musl" ;;
                aarch64|arm64)
                    err "Linux aarch64 is not yet supported by this installer."
                    err ""
                    err "grith's supervisor hard-codes x86_64 register"
                    err "names for syscall-arg extraction. aarch64 support"
                    err "needs an arch backend port. Track progress at:"
                    err "  https://github.com/${REPO}/issues"
                    err ""
                    err "If you have an x86_64 Linux machine or VM, you"
                    err "can install there via this same one-liner."
                    exit 1
                    ;;
                *)
                    err "Unsupported Linux architecture: ${arch}"
                    err "Currently supported: x86_64"
                    exit 1
                    ;;
            esac
            ;;
        Darwin)
            err "macOS is not yet supported by this installer."
            err ""
            err "grith's supervisor relies on Linux ptrace + seccomp."
            err "macOS support (via Endpoint Security) is targeted for"
            err "v2.0. Track progress at:"
            err "  https://github.com/${REPO}/issues"
            err ""
            err "If you have a Linux machine or VM, you can install"
            err "there via this same one-liner."
            exit 1
            ;;
        CYGWIN*|MINGW*|MSYS*|Windows*)
            err "Windows is not yet supported by this installer."
            err ""
            err "grith's supervisor relies on Linux ptrace + seccomp."
            err "Windows support (via ETW + a process supervisor) is"
            err "targeted for v2.0. Track progress at:"
            err "  https://github.com/${REPO}/issues"
            err ""
            err "If you have a Linux machine, VM, or WSL2, you can"
            err "install there via this same one-liner."
            exit 1
            ;;
        *)
            err "Unsupported operating system: ${os}"
            exit 1
            ;;
    esac

    printf '%s' "${target}"
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------
resolve_version() {
    if [ -n "${VERSION}" ]; then
        # Strip leading 'v' if present
        VERSION="$(printf '%s' "${VERSION}" | sed 's/^v//')"
        printf '%s' "${VERSION}"
        return
    fi

    info "Fetching latest version..."

    local latest_url="https://api.github.com/repos/${REPO}/releases/latest"
    local response

    if command -v curl >/dev/null 2>&1; then
        response="$(curl -sSL "${latest_url}" 2>/dev/null)" || true
    elif command -v wget >/dev/null 2>&1; then
        response="$(wget -qO- "${latest_url}" 2>/dev/null)" || true
    else
        err "Neither curl nor wget found. Cannot fetch latest version."
        exit 1
    fi

    if [ -z "${response}" ]; then
        err "Failed to fetch latest version from GitHub."
        err "Try specifying one explicitly: --version <X.Y.Z> (see releases on grith-ai/grith)"
        exit 1
    fi

    # Extract tag_name from JSON (simple grep, avoids jq dependency)
    local tag
    tag="$(printf '%s' "${response}" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"

    if [ -z "${tag}" ]; then
        err "Could not determine latest version from GitHub API response."
        exit 1
    fi

    # Strip leading 'v' if present
    tag="$(printf '%s' "${tag}" | sed 's/^v//')"
    printf '%s' "${tag}"
}

# ---------------------------------------------------------------------------
# Download & verify
# ---------------------------------------------------------------------------
download_and_install() {
    local version="$1"
    local target="$2"
    local install_dir="$3"

    local archive_file="${BINARY_NAME}-${version}-${target}.tar.gz"
    local checksum_file="${archive_file}.sha256"

    local base_url="${GRITH_RELEASE_BASE_URL:-https://github.com/${REPO}/releases/download/v${version}}"
    local archive_url="${base_url}/${archive_file}"
    local checksum_url="${base_url}/${checksum_file}"

    local tmpdir
    tmpdir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '${tmpdir}'" EXIT

    info "Downloading grith v${version} for ${target}..."

    # Download archive
    if command -v curl >/dev/null 2>&1; then
        curl -sSL --fail -o "${tmpdir}/${archive_file}" "${archive_url}" || {
            err "Failed to download archive from: ${archive_url}"
            err "Check that version v${version} exists at:"
            err "  https://github.com/${REPO}/releases"
            exit 1
        }
        curl -sSL --fail -o "${tmpdir}/${checksum_file}" "${checksum_url}" || {
            err "Failed to download checksum from: ${checksum_url}"
            exit 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "${tmpdir}/${archive_file}" "${archive_url}" || {
            err "Failed to download archive from: ${archive_url}"
            err "Check that version v${version} exists at:"
            err "  https://github.com/${REPO}/releases"
            exit 1
        }
        wget -q -O "${tmpdir}/${checksum_file}" "${checksum_url}" || {
            err "Failed to download checksum from: ${checksum_url}"
            exit 1
        }
    else
        err "Neither curl nor wget found."
        exit 1
    fi

    # Verify checksum
    info "Verifying SHA-256 checksum..."
    local expected_hash actual_hash

    expected_hash="$(awk '{print $1}' "${tmpdir}/${checksum_file}")"

    if command -v sha256sum >/dev/null 2>&1; then
        actual_hash="$(sha256sum "${tmpdir}/${archive_file}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual_hash="$(shasum -a 256 "${tmpdir}/${archive_file}" | awk '{print $1}')"
    else
        err "Neither sha256sum nor shasum found. Cannot verify checksum."
        exit 1
    fi

    if [ "${expected_hash}" != "${actual_hash}" ]; then
        err "Checksum verification FAILED!"
        err "  Expected: ${expected_hash}"
        err "  Actual:   ${actual_hash}"
        err ""
        err "The downloaded file may be corrupted or tampered with."
        err "Please try again or download manually from GitHub."
        exit 1
    fi

    ok "Checksum verified."

    # Extract archive
    info "Extracting..."
    tar xzf "${tmpdir}/${archive_file}" -C "${tmpdir}"

    if [ ! -f "${tmpdir}/${BINARY_NAME}" ]; then
        err "Expected binary not found in archive: ${BINARY_NAME}"
        exit 1
    fi

    # Install binary
    mkdir -p "${install_dir}"

    if [ -w "${install_dir}" ]; then
        cp "${tmpdir}/${BINARY_NAME}" "${install_dir}/${BINARY_NAME}"
        chmod +x "${install_dir}/${BINARY_NAME}"
    else
        info "Elevated permissions required to install to ${install_dir}"
        sudo cp "${tmpdir}/${BINARY_NAME}" "${install_dir}/${BINARY_NAME}"
        sudo chmod +x "${install_dir}/${BINARY_NAME}"
    fi

    ok "Installed grith to ${install_dir}/${BINARY_NAME}"
}

# ---------------------------------------------------------------------------
# PATH check
# ---------------------------------------------------------------------------
check_path() {
    local install_dir="$1"

    case ":${PATH:-}:" in
        *":${install_dir}:"*)
            return 0
            ;;
    esac

    warn "${install_dir} is not in your PATH."
    printf "\n"
    printf "  Add it to your shell profile:\n"
    printf "\n"

    local shell_name
    shell_name="$(basename "${SHELL:-/bin/sh}")"

    case "${shell_name}" in
        zsh)
            printf "    echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc\n" "${install_dir}"
            printf "    source ~/.zshrc\n"
            ;;
        bash)
            printf "    echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc\n" "${install_dir}"
            printf "    source ~/.bashrc\n"
            ;;
        fish)
            printf "    fish_add_path %s\n" "${install_dir}"
            ;;
        *)
            printf "    export PATH=\"%s:\$PATH\"\n" "${install_dir}"
            ;;
    esac
    printf "\n"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h)
                printf "grith installer\n\n"
                printf "Usage:\n"
                printf "  curl -fsSL https://grith.ai/install | sh\n"
                printf "  curl -fsSL https://grith.ai/install | sh -s -- --version <version>\n"
                printf "  curl -fsSL https://grith.ai/install | sh -s -- --global\n\n"
                printf "Options:\n"
                printf "  --version <ver>  Install a specific version (default: latest)\n"
                printf "  --global         Install to /usr/local/bin instead of ~/.local/bin\n"
                printf "  --help           Show this help message\n"
                exit 0
                ;;
            --version)
                if [ $# -lt 2 ]; then
                    err "--version requires a value"
                    exit 1
                fi
                VERSION="$2"
                shift 2
                ;;
            --global)
                GLOBAL_INSTALL=true
                INSTALL_DIR="/usr/local/bin"
                shift
                ;;
            *)
                err "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    printf "\n"
    printf "  \033[1mgrith installer\033[0m\n"
    printf "  Zero Trust for AI Agents\n"
    printf "\n"

    # Check basic requirements
    need_cmd uname
    need_cmd mktemp
    need_cmd tar

    # Detect platform
    local target
    target="$(detect_platform)"
    info "Detected platform: ${target}"

    # Resolve version
    local version
    version="$(resolve_version)"
    info "Version: ${version}"

    # Install
    if [ "${GLOBAL_INSTALL}" = true ]; then
        info "Install directory: ${INSTALL_DIR} (global)"
    else
        info "Install directory: ${INSTALL_DIR}"
    fi

    download_and_install "${version}" "${target}" "${INSTALL_DIR}"

    # Check PATH
    check_path "${INSTALL_DIR}"

    # Success message
    printf "\n"
    ok "grith v${version} installed successfully!"
    printf "\n"
    printf "  Next steps:\n"
    printf "    1. Verify the installation:  grith --version\n"
    printf "    2. Initialize a project:     grith init\n"
    printf "    3. Start an interactive run: grith\n"
    printf "    4. Read the docs:            https://docs.grith.ai\n"
    printf "\n"
}

main "$@"
