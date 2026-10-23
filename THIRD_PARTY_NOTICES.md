# Third-party notices

Voice Channel itself is released under the MIT License (see [LICENSE](LICENSE)). It uses the components below. Licenses were checked in the package metadata of the exact versions that are pinned in this repository, and in the license headers shipped with the files.

## Live mode (browser)

These files are not stored in this repository. `deploy.sh` downloads them from the npm registry (through the jsdelivr or unpkg mirror) and checks them against the checksums in `web/vendor.lock`. The server then serves them itself.

| Component | Version | License | Files | Source |
|---|---|---|---|---|
| Silero VAD (voice activity detection model, v5) | as shipped in `@ricky0123/vad-web` 0.0.30 | MIT, Copyright (c) 2020-present Silero Team | `silero_vad_v5.onnx` | https://github.com/snakers4/silero-vad |
| `@ricky0123/vad-web` | 0.0.30 | ISC, Copyright (c) 2022-present ricky0123 | `vad.bundle.min.js`, `vad.worklet.bundle.min.js` | https://github.com/ricky0123/vad |
| `onnxruntime-web` | 1.22.0 | MIT, Copyright (c) Microsoft Corporation | `ort-wasm-simd-threaded.mjs`, `ort-wasm-simd-threaded.wasm`, and the JavaScript API inside `vad.bundle.min.js` | https://github.com/microsoft/onnxruntime |

## Channel server (Bun)

Bundled into `channel/dist/server.js` by `deploy.sh`. Direct dependencies are pinned in `channel/package.json`; every package below them is pinned with an integrity hash in `channel/bun.lock`.

| Component | Version | License |
|---|---|---|
| `@modelcontextprotocol/sdk` | 1.32.1 | MIT |
| `zod` | 3.25.76 | MIT |

The SDK brings 90 further packages (listed with exact versions in `channel/bun.lock`). Their licenses, read from each package's own `package.json`: MIT for 80 of them, ISC for `inherits`, `isexe`, `once`, `setprototypeof`, `which`, `wrappy` and `zod-to-json-schema`, BSD-3-Clause for `fast-uri` and `qs`, and BSD-2-Clause for `json-schema-typed`. All of these licenses require that their copyright and license notice stay with copies of the software; the notices are in the packages themselves, which you can see with `bun install` in `channel/`.

## Loaded from outside at run time

The Mini App page loads Telegram's own script from `https://telegram.org/js/telegram-web-app.js`. It is not part of this repository and is governed by Telegram's terms.

## Not bundled

The deploy needs, but does not ship: Bun, cloudflared, Python, curl, rsync, tmux and systemd. Each has its own license.

## Services

Speech recognition and synthesis go through OpenRouter (your own account and key). Its terms apply to your use of it.
