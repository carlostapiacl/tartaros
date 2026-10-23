# @carlostapiacl/tartaros

Prebuilt [tartaros](https://github.com/carlostapiacl/tartaros) for npm: run a command
confined by a policy, on the OS's own sandbox (Seatbelt on macOS, Landlock and
namespaces on Linux, AppContainer on Windows).

```sh
npm i -g @carlostapiacl/tartaros
tartaros --version
```

The binary comes in one optional dependency per platform, and npm installs only
the one that matches: `@carlostapiacl/tartaros-darwin-arm64`, `-darwin-x64`,
`-linux-arm64`, `-linux-x64` (static, musl) and `-win32-x64`. Installing with
`--omit=optional` leaves it out.

From node, without going through the `bin` wrapper:

```js
const { binaryPath } = require("@carlostapiacl/tartaros");
binaryPath(); // absolute path to this platform's tartaros binary
```

The same binaries, with their SHA-256, are attached to each
[GitHub release](https://github.com/carlostapiacl/tartaros/releases).
