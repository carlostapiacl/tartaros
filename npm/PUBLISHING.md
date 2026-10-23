# Publishing tartaros to npm

`.github/workflows/release.yml` builds, on a `v*` tag, the five binaries, a GitHub
release with them and `SHA256SUMS`, and six npm packages packed from exactly those
binaries (attached to the release as `.tgz`):

| package | holds |
|---|---|
| `@carlostapiacl/tartaros` | the `tartaros` bin and `binaryPath()`; the five below as `optionalDependencies` |
| `@carlostapiacl/tartaros-darwin-arm64` | `bin/tartaros`, `aarch64-apple-darwin` |
| `@carlostapiacl/tartaros-darwin-x64` | `bin/tartaros`, `x86_64-apple-darwin` |
| `@carlostapiacl/tartaros-linux-arm64` | `bin/tartaros`, `aarch64-unknown-linux-gnu`, glibc 2.35+ |
| `@carlostapiacl/tartaros-linux-x64` | `bin/tartaros`, `x86_64-unknown-linux-gnu`, glibc 2.35+ |
| `@carlostapiacl/tartaros-win32-x64` | `bin/tartaros.exe`, `x86_64-pc-windows-msvc` |

## The first version, by hand (once)

npm cannot configure a trusted publisher for a package that does not exist, so the
first version of each package is published from a laptop, from the release's own
`.tgz` files (what CI built, not a local build):

```sh
npm login                         # the npm account that owns the @carlostapiacl scope
v=0.1.0-alpha.12                  # the tag, without the v
d=$(mktemp -d) && cd "$d"
gh release download "v$v" -R carlostapiacl/tartaros -p '*.tgz'
for t in carlostapiacl-tartaros-*-*-"$v".tgz; do npm publish "$t" --access public --tag latest; done
npm publish "carlostapiacl-tartaros-$v.tgz" --access public --tag latest
```

Platform packages first, the main one last. `--tag latest` because npm 11 refuses
a prerelease without an explicit dist-tag, and `latest` is what a plain
`npm i -g @carlostapiacl/tartaros` installs. This first version has no
provenance.

## Trusted publishing (once per package)

On npmjs.com, for **each of the six packages**: Settings → Trusted publishing →
GitHub Actions, with

- Organization or user: `carlostapiacl`
- Repository: `tartaros`
- Workflow filename: `release.yml`
- Environment name: (empty)

Then, in the repository: Settings → Secrets and variables → Actions → Variables,
`NPM_TRUSTED_PUBLISHING` = `true`. From the next tag on, the `npm` job publishes
with provenance and no token. Optionally, set each package to "require 2FA and
disallow tokens" once a CI publish has gone through.
