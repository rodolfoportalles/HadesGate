# typed: false
# frozen_string_literal: true

require "securerandom"

# The sha256 values below must be taken from the SHA256SUMS asset of the
# release being published. `brew audit --strict` rejects a URL without one.
class Hadesgate < Formula
  desc "Zero-PII Privacy Gateway & Tactical Shield for LLMs (OpenAI, Anthropic, Gemini)"
  homepage "https://hadesgate.dev"
  version "2.0.0"
  license "AGPL-3.0-only"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/hadesgate/hadesgate/releases/download/v#{version}/hadesgate-darwin-amd64.tar.gz"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
    if Hardware::CPU.arm?
      url "https://github.com/hadesgate/hadesgate/releases/download/v#{version}/hadesgate-darwin-arm64.tar.gz"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/hadesgate/hadesgate/releases/download/v#{version}/hadesgate-linux-amd64.tar.gz"
      sha256 "REPLACE_WITH_LINUX_AMD64_SHA256"
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/hadesgate/hadesgate/releases/download/v#{version}/hadesgate-linux-arm64.tar.gz"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    end
  end

  def install
    bin.install "hadesgate"
    etc.install ".env.example" => "hadesgate.env.example" if File.exist?(".env.example")

    # brew services cannot pass a literal secret without rewriting the formula,
    # so the launcher loads the operator's file and the service stays generic.
    (bin/"hadesgate-launch").write <<~SH
      #!/bin/sh
      set -a
      [ -f "${HADESGATE_ENV_FILE:-$HOME/.hadesgate/.env}" ] && . "${HADESGATE_ENV_FILE:-$HOME/.hadesgate/.env}"
      set +a
      exec "#{opt_bin}/hadesgate" "$@"
    SH
    chmod 0755, bin/"hadesgate-launch"
  end

  def post_install
    (var/"hadesgate").mkpath
    (var/"log").mkpath
    config_dir = Pathname.new(Dir.home)/".hadesgate"
    config_dir.mkpath
    env_file = config_dir/".env"
    return if env_file.exist?

    # Fail visible: without a master key the binary refuses to start.
    env_file.write <<~ENV
      HADESGATE_BIND_ADDRESS=127.0.0.1
      HADESGATE_PORT=8080
      HADESGATE_DB_PATH=#{var}/hadesgate/hadesgate.db
      HADESGATE_ADMIN_KEY=#{SecureRandom.hex(32)}
      HADESGATE_CONFIG_MASTER_KEY=#{SecureRandom.base64(32)}
    ENV
    chmod 0600, env_file
    opoo "Chaves geradas em #{env_file}. Guarde HADESGATE_CONFIG_MASTER_KEY fora desta máquina."
  end

  service do
    run [opt_bin/"hadesgate-launch"]
    keep_alive true
    working_dir var/"hadesgate"
    log_path var/"log/hadesgate.log"
    error_log_path var/"log/hadesgate.log"
  end

  test do
    assert_predicate bin/"hadesgate", :exist?
    assert_match "Usage", shell_output("#{bin}/hadesgate -h 2>&1", 2)
  end
end
