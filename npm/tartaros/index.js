"use strict";
// Where the tartaros binary for this platform lives. The binary ships in one
// optional dependency per platform (@carlostapiacl/tartaros-<platform>-<arch>);
// npm installs only the one whose `os` and `cpu` match.

const path = require("path");

const SCOPE = "@carlostapiacl";
const SUPPORTED = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-x64"];

function platformPackage(platform = process.platform, arch = process.arch) {
  return `${SCOPE}/tartaros-${platform}-${arch}`;
}

function binaryPath() {
  const key = `${process.platform}-${process.arch}`;
  if (!SUPPORTED.includes(key)) {
    throw new Error(`tartaros has no prebuilt binary for ${key} (prebuilt: ${SUPPORTED.join(", ")})`);
  }
  const pkg = platformPackage();
  const exe = process.platform === "win32" ? "tartaros.exe" : "tartaros";
  let dir;
  try {
    dir = path.dirname(require.resolve(`${pkg}/package.json`));
  } catch {
    throw new Error(
      `${pkg} is not installed. It is an optional dependency of @carlostapiacl/tartaros, ` +
        `so it is skipped by --omit=optional or --no-optional, or by a lockfile made on another ` +
        `platform. Reinstall with optional dependencies: npm i -g @carlostapiacl/tartaros`,
    );
  }
  return path.join(dir, "bin", exe);
}

module.exports = { binaryPath, platformPackage, SUPPORTED };
