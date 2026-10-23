#!/usr/bin/env node
"use strict";
// npm's `bin` for @carlostapiacl/tartaros: run the platform's binary with the
// same arguments and stdio, and exit the way it exited. Callers that want to
// skip node can run binaryPath() from the package directly.

const { spawnSync } = require("child_process");
const { binaryPath } = require("..");

let bin;
try {
  bin = binaryPath();
} catch (e) {
  console.error(`tartaros: ${e.message}`);
  process.exit(1);
}

const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (r.error) {
  console.error(`tartaros: cannot run ${bin}: ${r.error.message}`);
  process.exit(1);
}
if (r.signal) {
  process.kill(process.pid, r.signal);
}
process.exit(r.status ?? 1);
