#!/usr/bin/env node
// Builds the npm packages from the release binaries, esbuild-style: one package
// per platform holding its binary, and @carlostapiacl/tartaros depending on all
// of them as optionalDependencies. Then `npm pack`s each one.
//
//   node npm/build.mjs --version 0.1.0-alpha.11 --bins dist/bin --out dist/npm [--allow-missing]
//
// --bins holds tartaros-<platform>-<arch> (tartaros-win32-x64.exe on Windows).
// --allow-missing packs only the platforms present, for a local try; a release
// needs all of them, or npm would install a main package whose binary is missing.

import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const { SUPPORTED, platformPackage } = createRequire(import.meta.url)("./tartaros/index.js");

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const version = opt("--version");
const bins = opt("--bins");
const out = opt("--out");
const allowMissing = args.includes("--allow-missing");
if (!version || !bins || !out) {
  console.error("usage: build.mjs --version V --bins DIR --out DIR [--allow-missing]");
  process.exit(2);
}

// The version npm gets is the crate's: a tag that disagrees is a mistake.
const cargo = readFileSync(join(root, "Cargo.toml"), "utf8").match(/^version = "([^"]+)"/m)?.[1];
if (cargo !== version) {
  console.error(`version ${version} is not the workspace's (${cargo})`);
  process.exit(1);
}

const common = {
  version,
  license: "Apache-2.0",
  author: "Carlos Tapia",
  homepage: "https://github.com/carlostapiacl/tartaros",
  repository: { type: "git", url: "git+https://github.com/carlostapiacl/tartaros.git" },
  bugs: { url: "https://github.com/carlostapiacl/tartaros/issues" },
};
const legal = ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"];

mkdirSync(out, { recursive: true });
const packed = [];
const pack = (dir) => {
  const name = execFileSync("npm", ["pack", "--pack-destination", resolve(out), "--silent"], { cwd: dir, encoding: "utf8" }).trim();
  packed.push(name);
};

const present = [];
for (const key of SUPPORTED) {
  const [platform, cpu] = key.split("-");
  const exe = platform === "win32" ? "tartaros.exe" : "tartaros";
  const src = join(bins, platform === "win32" ? `tartaros-${key}.exe` : `tartaros-${key}`);
  if (!existsSync(src)) {
    if (allowMissing) continue;
    console.error(`missing ${src}`);
    process.exit(1);
  }
  present.push(key);
  const dir = join(out, "pkg", `tartaros-${key}`);
  mkdirSync(join(dir, "bin"), { recursive: true });
  copyFileSync(src, join(dir, "bin", exe));
  chmodSync(join(dir, "bin", exe), 0o755);
  for (const f of legal) copyFileSync(join(root, f), join(dir, f));
  const pkg = {
    name: platformPackage(platform, cpu),
    ...common,
    description: `The tartaros binary for ${key}. Install @carlostapiacl/tartaros instead.`,
    os: [platform],
    cpu: [cpu],
    files: ["bin", ...legal],
    preferUnplugged: true,
  };
  writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
  writeFileSync(join(dir, "README.md"), `# ${pkg.name}\n\n${pkg.description}\n`);
  pack(dir);
}

const main = join(out, "pkg", "tartaros");
cpSync(join(here, "tartaros"), main, { recursive: true });
for (const f of legal) copyFileSync(join(root, f), join(main, f));
const mainPkg = {
  name: "@carlostapiacl/tartaros",
  ...common,
  description: "Run a command confined by a policy, on the OS's own sandbox. Prebuilt binaries.",
  keywords: ["sandbox", "landlock", "seatbelt", "appcontainer", "agents"],
  main: "index.js",
  bin: { tartaros: "bin/tartaros.js" },
  files: ["index.js", "bin", "README.md", ...legal],
  engines: { node: ">=18" },
  optionalDependencies: Object.fromEntries(
    (allowMissing ? present : SUPPORTED).map((key) => [platformPackage(...key.split("-")), version]),
  ),
};
writeFileSync(join(main, "package.json"), JSON.stringify(mainPkg, null, 2) + "\n");
chmodSync(join(main, "bin", "tartaros.js"), 0o755);
pack(main);

console.log(packed.join("\n"));
