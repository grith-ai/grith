# typed: false
# frozen_string_literal: true

# NOTE: Homebrew distribution is deferred from the v1 launch.
# SHA-256 placeholders below must be replaced with real hashes from the
# GitHub Release assets before this formula is published to a tap.
# See docs/RELEASE.md for the post-release package-manager update steps.

class Grith < Formula
  desc "Zero Trust for AI Agents - Security proxy for local AI agent platforms"
  homepage "https://grith.ai"
  version "0.1.0"
  license "MPL-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/grith-ai/grith/releases/download/v#{version}/grith-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_MACOS_ARM64"
    else
      url "https://github.com/grith-ai/grith/releases/download/v#{version}/grith-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_MACOS_X86_64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/grith-ai/grith/releases/download/v#{version}/grith-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/grith-ai/grith/releases/download/v#{version}/grith-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_X86_64"
    end
  end

  def install
    bin.install "grith"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/grith --version")
  end
end
