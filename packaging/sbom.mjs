// CycloneDX 1.5 SBOM for one release binary: the crates compiled into
// tartaros-cli for that target, from `cargo metadata` and Cargo.lock (normal
// dependencies only; build scripts and dev-dependencies do not ship).
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

const meta = JSON.parse(
  execFileSync(
    "cargo",
    ["metadata", "--format-version", "1", "--locked", "--filter-platform", target],
    { encoding: "utf8", maxBuffer: 64 << 20 },
  ),
);
const pkgs = new Map(meta.packages.map((p) => [p.id, p]));
const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
const root = meta.packages.find((p) => p.name === "tartaros-cli");
if (!root) {
  console.error("tartaros-cli is not in the workspace");
  process.exit(1);
}

// Cargo.lock checksums, for the crates that come from crates.io.
const checksum = new Map();
for (const block of readFileSync(new URL("../Cargo.lock", import.meta.url), "utf8").split("[[package]]")) {
  const name = block.match(/^name = "(.*)"$/m)?.[1];
  const ver = block.match(/^version = "(.*)"$/m)?.[1];
  const sum = block.match(/^checksum = "(.*)"$/m)?.[1];
  if (name && ver && sum) checksum.set(`${name}@${ver}`, sum);
}

// Walk the normal dependencies from tartaros-cli.
const shipped = new Set();
const todo = [root.id];
while (todo.length) {
  const id = todo.pop();
  if (shipped.has(id)) continue;
  shipped.add(id);
  for (const d of nodes.get(id)?.deps ?? []) {
    if (d.dep_kinds.some((k) => k.kind === null)) todo.push(d.pkg);
  }
}

const ref = (p) => `${p.name}@${p.version}`;
const component = (p) => {
  const c = {
    type: p.id === root.id ? "application" : "library",
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

const ids = [...shipped].sort();
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
      "bom-ref": `tartaros@${version}`,
      name: basename(binary),
      version,
      hashes: [{ alg: "SHA-256", content: createHash("sha256").update(bin).digest("hex") }],
      properties: [{ name: "cargo:target", value: target }],
    },
  },
  components: ids.map((id) => component(pkgs.get(id))),
  dependencies: ids.map((id) => ({
    ref: ref(pkgs.get(id)),
    dependsOn: (nodes.get(id)?.deps ?? [])
      .filter((d) => d.dep_kinds.some((k) => k.kind === null))
      .map((d) => ref(pkgs.get(d.pkg)))
      .sort(),
  })),
};
process.stdout.write(JSON.stringify(bom, null, 2) + "\n");
