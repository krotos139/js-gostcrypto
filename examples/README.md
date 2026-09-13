# Examples

Each directory is a small application built against the public
`@gostcrypto/*` API.

| Directory | Run | Purpose |
|---|---|---|
| `node` | `npm install && npm run hash -- ../../README.md 512` | Hash files and sign files with a PFX certificate |
| `react` | `npm install && npm run dev` | React certificate selector and CryptoPro USB-token signing |
| `angularjs` | `npm install && npm run dev` | AngularJS certificate-provider integration |
| `jquery` | `npm install && npm run dev` | jQuery certificate-provider integration |
| `cryptopro-browser` | From repository root: `npm run test:browser:cryptopro` | Bundler-free CryptoPro browser test |

The browser examples load the official CryptoPro `cadesplugin_api.js`. Install
and enable the CryptoPro browser extension, connect the token, then open the
local URL printed by Vite. The private key remains inside CryptoPro CSP or the
USB token.

The examples intentionally contain no passwords, bearer tokens, certificates,
private keys, or machine-specific paths.
