# Makefile — Developer build routines for grith
#
# Usage:
#   make              # Show help
#   make build        # Debug build
#   make release      # Optimised release build
#   make install      # Release build + install to ~/.local/bin
#   make all          # lint → test → release → dashboard
#
# Overridable variables:
#   INSTALL_DIR    Install directory   (default: ~/.local/bin)
#   BINARY_NAME    Binary name         (default: grith)

INSTALL_DIR  ?= $(HOME)/.local/bin
BINARY_NAME  ?= grith
CARGO        := cargo
NPM          := npm

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------
.PHONY: help build release dashboard install test lint clean all completions dist dist-all dist-test

help: ## Show available targets
	@printf "\n  \033[1mgrith\033[0m — build targets\n\n"
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@printf "\n  Override with: make install INSTALL_DIR=/usr/local/bin\n\n"

build: ## Debug build (grith-core)
	$(CARGO) build -p grith-core

release: ## Optimised release build (grith-core)
	$(CARGO) build --release -p grith-core

dashboard: ## Build the React dashboard (npm install + vite build)
	@if ! command -v node >/dev/null 2>&1; then \
		printf "\033[1;31m[error]\033[0m Node.js not found. Dashboard build requires Node.js 20+.\n"; \
		exit 1; \
	fi
	cd dashboard && $(NPM) install && $(NPM) run build

install: release ## Release build + install binary to INSTALL_DIR
	@mkdir -p "$(INSTALL_DIR)"
	cp target/release/$(BINARY_NAME) "$(INSTALL_DIR)/$(BINARY_NAME)"
	chmod +x "$(INSTALL_DIR)/$(BINARY_NAME)"
	@printf "\033[1;32m[ok]\033[0m    Installed $(BINARY_NAME) to $(INSTALL_DIR)/$(BINARY_NAME)\n"
	@$(MAKE) --no-print-directory completions

test: ## Run all workspace tests
	$(CARGO) test --workspace

lint: ## Run cargo fmt check + clippy
	$(CARGO) fmt --check
	$(CARGO) clippy --workspace -- -D warnings

clean: ## Clean build artifacts and dashboard dist
	$(CARGO) clean
	rm -rf dashboard/dist

all: lint test release dashboard ## Full pipeline: lint → test → release → dashboard

# ---------------------------------------------------------------------------
# Distribution targets
# ---------------------------------------------------------------------------
VERSION := $(shell grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
DIST_DIR := dist/release-artifacts

dist: dashboard ## Build the best available local dist archive for the current platform
	./scripts/build-release.sh --host-target

dist-all: dashboard ## Build distributable archives for all release targets (requires cross for Linux musl)
	./scripts/build-release.sh

dist-test: dist ## Stage local release assets and run the real installer against them
	@printf "\n\033[1;34m[info]\033[0m  Testing install script against local release assets...\n"
	@TARGET="$$(./scripts/build-release.sh --print-host-target)"; \
	CANONICAL_TARGET="$$(./scripts/build-release.sh --print-canonical-host-target)"; \
	ARCHIVE="$(BINARY_NAME)-$(VERSION)-$${TARGET}.tar.gz"; \
	RELEASE_STAGE="$$(mktemp -d)"; \
	HOME_TMP="$$(mktemp -d)"; \
	trap "rm -rf '$${RELEASE_STAGE}' '$${HOME_TMP}'" EXIT; \
	cp "$(DIST_DIR)/$${ARCHIVE}" "$${RELEASE_STAGE}/"; \
	cp "$(DIST_DIR)/$${ARCHIVE}.sha256" "$${RELEASE_STAGE}/"; \
	if [ "$${TARGET}" != "$${CANONICAL_TARGET}" ]; then \
		export GRITH_INSTALL_FORCE_TARGET="$${TARGET}"; \
		printf "\033[1;33m[warn]\033[0m  Using install target override for local fallback artifact: $${TARGET}\n"; \
	fi; \
	PATH="$${HOME_TMP}/.local/bin:$$PATH" \
	HOME="$${HOME_TMP}" \
	GRITH_RELEASE_BASE_URL="file://$${RELEASE_STAGE}" \
	sh ./scripts/install.sh --version "$(VERSION)"; \
	if [ ! -x "$${HOME_TMP}/.local/bin/$(BINARY_NAME)" ]; then \
		printf "\033[1;31m[error]\033[0m Installed binary not found in $${HOME_TMP}/.local/bin\n"; \
		exit 1; \
	fi; \
	VER=$$("$${HOME_TMP}/.local/bin/$(BINARY_NAME)" --version 2>/dev/null || echo "unknown"); \
	printf "\033[1;32m[ok]\033[0m    Installer placed runnable binary: $${VER}\n"

completions: ## Install shell completions (graceful no-op if unsupported)
	@if [ -f "target/release/$(BINARY_NAME)" ]; then \
		if target/release/$(BINARY_NAME) completions bash >/dev/null 2>&1; then \
			mkdir -p "$(HOME)/.local/share/bash-completion/completions"; \
			target/release/$(BINARY_NAME) completions bash > "$(HOME)/.local/share/bash-completion/completions/$(BINARY_NAME)" 2>/dev/null && \
				printf "\033[1;32m[ok]\033[0m    Installed bash completions\n" || true; \
			if [ -d "$(HOME)/.zsh" ] || command -v zsh >/dev/null 2>&1; then \
				mkdir -p "$(HOME)/.zsh/completions"; \
				target/release/$(BINARY_NAME) completions zsh > "$(HOME)/.zsh/completions/_$(BINARY_NAME)" 2>/dev/null && \
					printf "\033[1;32m[ok]\033[0m    Installed zsh completions\n" || true; \
			fi; \
			if command -v fish >/dev/null 2>&1; then \
				mkdir -p "$(HOME)/.config/fish/completions"; \
				target/release/$(BINARY_NAME) completions fish > "$(HOME)/.config/fish/completions/$(BINARY_NAME).fish" 2>/dev/null && \
					printf "\033[1;32m[ok]\033[0m    Installed fish completions\n" || true; \
			fi; \
		else \
			printf "\033[1;33m[warn]\033[0m  Shell completions not yet supported by $(BINARY_NAME); skipping.\n"; \
		fi; \
	else \
		printf "\033[1;33m[warn]\033[0m  Binary not built; skipping completions. Run 'make release' first.\n"; \
	fi
