// Homebrew formula for a release, from its SHA256SUMS: the prebuilt binaries
// the release ships (macOS arm64/x64, Linux arm64/x64), not a source build.
// Usage: node packaging/brew-formula.mjs VERSION SHA256SUMS > tartaros.rb
import { readFileSync } from "node:fs";

const [version, sums] = process.argv.slice(2);
if (!version || !sums) {
  console.error("usage: brew-formula.mjs VERSION SHA256SUMS");
  process.exit(2);
}
const sha = {};
for (const line of readFileSync(sums, "utf8").split("\n")) {
  const [h, f] = line.trim().split(/\s+/);
  if (h && f) sha[f.replace(/^\*/, "")] = h;
}
const url = (p) => `https://github.com/carlostapiacl/tartaros/releases/download/v${version}/tartaros-${p}`;
const one = (p) => {
  if (!sha[`tartaros-${p}`]) {
    console.error(`no checksum for tartaros-${p}`);
    process.exit(1);
  }
  return `url "${url(p)}"\n      sha256 "${sha[`tartaros-${p}`]}"`;
};
process.stdout.write(`class Tartaros < Formula
  desc "Sandbox for coding agents: Seatbelt on macOS, Landlock and seccomp on Linux"
  homepage "https://github.com/carlostapiacl/tartaros"
  version "${version}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      ${one("darwin-arm64")}
    end
    on_intel do
      ${one("darwin-x64")}
    end
  end

  on_linux do
    on_arm do
      ${one("linux-arm64")}
    end
    on_intel do
      ${one("linux-x64")}
    end
  end

  def install
    bin.install Dir["tartaros-*"].first => "tartaros"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tartaros version")
  end
end
`);
