// CycloneDX 1.5 SBOM for one release binary: the crates compiled into
// tartaros-cli for that target. The graph comes from `cargo tree -p tartaros-cli`,
// which resolves features the way the release build does (`cargo metadata`
// resolves them for the whole workspace, test tools included); normal
// dependencies only, build scripts and dev-dependencies do not ship. Licenses
// and sources come from `cargo metadata`, checksums from Cargo.lock.
// Usage: node packaging/sbom.mjs VERSION TARGET BINARY > tartaros-<platform>.cdx.json
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";

const [version, target, binary] = process.argv.slice(2);
if (!version || !target || !binary) {
  console.error("usage: sbom.mjs VERSION TARGET BINARY");
  process.exit(2);
}

const cargo = (args) => execFileSync("cargo", args, { encoding: "utf8", maxBuffer: 64 << 20 });
const meta = JSON.parse(cargo(["metadata", "--format-version", "1", "--locked", "--filter-platform", target]));
const byRef = new Map(meta.packages.map((p) => [`${p.name}@${p.version}`, p]));

// Cargo.lock checksums, for the crates that come from crates.io.
const checksum = new Map();
for (const block of readFileSync(new URL("../Cargo.lock", import.meta.url), "utf8").split("[[package]]")) {
  const name = block.match(/^name = "(.*)"$/m)?.[1];
  const ver = block.match(/^version = "(.*)"$/m)?.[1];
  const sum = block.match(/^checksum = "(.*)"$/m)?.[1];
  if (name && ver && sum) checksum.set(`${name}@${ver}`, sum);
}

// `cargo tree --prefix depth`: one crate per line, its depth first. A crate
// already printed is marked (*) and its children are not repeated.
const tree = cargo([
  "tree", "--locked", "-p", "tartaros-cli", "--target", target,
  "-e", "normal", "--prefix", "depth", "--format", "{p}",
]);
const edges = new Map();
const stack = [];
let rootRef;
for (const line of tree.split("\n")) {
  const m = line.match(/^(\d+)(\S+) v(\S+)/);
  if (!m) continue;
  const depth = Number(m[1]);
  const r = `${m[2]}@${m[3]}`;
  if (!byRef.has(r)) {
    console.error(`cargo tree names ${r}, which cargo metadata does not have`);
    process.exit(1);
  }
  if (depth === 0) rootRef = r;
  stack.length = depth;
  if (depth > 0) edges.get(stack[depth - 1]).add(r);
  if (!edges.has(r)) edges.set(r, new Set());
  stack.push(r);
}
if (!rootRef || !rootRef.startsWith("tartaros-cli@")) {
  console.error("cargo tree did not start at tartaros-cli");
  process.exit(1);
}

const ref = (p) => `${p.name}@${p.version}`;
const component = (p) => {
  const c = {
    type: ref(p) === rootRef ? "application" : "library",
    "bom-ref": ref(p),
    name: p.name,
    version: p.version,
    purl: `pkg:cargo/${p.name}@${p.version}`,
  };
  if (p.license) c.licenses = [{ expression: p.license }];
  const sum = checksum.get(ref(p));
  if (sum) c.hashes = [{ alg: "SHA-256", content: sum }];
  if (!p.source) c.purl = undefined; // a workspace crate is not on crates.io
  if (p.repository) c.externalReferences = [{ type: "vcs", url: p.repository }];
  return c;
};

const refs = [...edges.keys()].sort();
const binRef = `tartaros@${version}`;
const bin = readFileSync(binary);
const bom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: { components: [{ type: "application", name: "packaging/sbom.mjs" }] },
    component: {
      type: "application",
      "bom-ref": binRef,
      name: basename(binary),
      version,
      hashes: [{ alg: "SHA-256", content: createHash("sha256").update(bin).digest("hex") }],
      properties: [{ name: "cargo:target", value: target }],
    },
  },
  components: refs.map((r) => component(byRef.get(r))),
  // The binary is built from tartaros-cli, so the graph starts there.
  dependencies: [
    { ref: binRef, dependsOn: [rootRef] },
    ...refs.map((r) => ({ ref: r, dependsOn: [...edges.get(r)].sort() })),
  ],
};
process.stdout.write(JSON.stringify(bom, null, 2) + "\n");
