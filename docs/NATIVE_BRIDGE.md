# Certificate bridge protocol

The browser-facing provider and the Node.js agent use JSON-RPC 2.0 over an
HTTP `POST`. The bridge exposes only certificate enumeration, native trust
validation and signing; private keys are never returned to browser JavaScript.

## Direct CryptoPro browser plug-in

When the official CryptoPro extension and its `cadesplugin_api.js` script are
available, no HTTP agent is required. `@gostcrypto/providers` adapts the
asynchronous CAdESCOM API to the common `CertificateProvider` contract:

```js
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

const provider = createCryptoProBrowserProvider();
const certificates = await provider.listCertificates();
const trust = await provider.validateCertificate(certificates[0].id);
const signature = await provider.sign(certificates[0].id, documentBytes, {
  algorithm: "gost3410-2012-256",
  detached: true,
  checkCertificate: true,
});
```

The vendor script is deliberately not bundled. An application remains in
control of extension installation, its content-security policy, and the
version of the CryptoPro API it loads. For module loaders, the initialized
plug-in object or promise can be supplied explicitly as `{ plugin }`.

For a manual test against the real browser extension and a hardware token,
run `npm run test:browser:cryptopro` and open the printed loopback URL in
Chrome. The smoke page lists and validates certificates through
`CryptoProBrowserCertificateProvider`, signs text or an arbitrary file,
downloads the detached CAdES-BES signature as `.p7s`, and verifies a generated
or uploaded signature with the JavaScript implementation. Enter a token PIN
only in the CryptoPro/token dialog; the page never asks for or reads it.

## Starting an agent

### Command-line launcher

The `@gostcrypto/node` package publishes a `gostcrypto-bridge` executable.
It reads the bearer token from an environment variable, never from a command
argument, and requires TLS unless insecure HTTP is explicitly enabled for
local development:

```powershell
npm install --global @gostcrypto/node
$env:GOSTCRYPTO_BRIDGE_TOKEN = "a-random-secret-containing-at-least-32-characters"
gostcrypto-bridge --origin https://documents.example `
  --tls-cert ./certs/localhost.crt --tls-key ./certs/localhost.key
```

Multiple `--origin` options are accepted. The default bind address is
`127.0.0.1` and the default port is `19443`. Use `--allow-http` only for a
local HTTP page during development; browsers block an HTTPS page from calling
an insecure endpoint.

### CryptoPro system store

On Windows, `CryptoProCertificateProvider` uses the installed CryptoPro
CAdESCOM component and the current user's `My` store. The private key remains
inside the CSP or token. Communication with Windows PowerShell uses JSON on
standard input, so document contents, bearer tokens and certificate
thumbprints are not placed in process arguments.

```js
import {
  createCertificateBridgeServer,
  createCryptoProCertificateProvider,
} from "@gostcrypto/node";

const provider = createCryptoProCertificateProvider();
const server = createCertificateBridgeServer(provider, {
  bearerToken: process.env.BRIDGE_TOKEN,
  allowedOrigins: ["https://documents.example"],
});
server.listen(19443, "127.0.0.1");
```

By default the provider starts 64-bit Windows PowerShell 5.1 in STA mode and
automatically retries the 32-bit host when COM reports its characteristic
registration mismatch. To force a 32-bit-only CSP, set `powershellPath` to
`C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe`. The provider
checks that the requested 256- or 512-bit GOST algorithm matches the selected
certificate and creates a CAdES-BES/CMS signature. It first opens the store
through CAdESCOM and falls back to the API-compatible CAPICOM store used by
some 32-bit CryptoPro installations.

### PFX file

```js
import { createCertificateBridgeServer, openPfxFile } from "@gostcrypto/node";

const provider = await openPfxFile("signing-key.pfx", process.env.PFX_PASSWORD);
const server = createCertificateBridgeServer(provider, {
  bearerToken: process.env.BRIDGE_TOKEN,
  allowedOrigins: ["https://documents.example"],
});
server.listen(19443, "127.0.0.1");
```

`createCertificateBridgeHandler` can instead be passed to
`node:https.createServer` when the agent has a locally trusted TLS
certificate. Production integrations should use HTTPS, bind to loopback,
generate a high-entropy token per installation or session, and explicitly
allow only the application origins that need signing access.

## Methods

`certificates.list` accepts an empty object and returns certificate metadata:

```json
{"jsonrpc":"2.0","id":1,"method":"certificates.list","params":{}}
```

Binary DER is base64 and dates are ISO 8601 strings.
`certificates.validate` asks the native trust engine to check a certificate:

```json
{"jsonrpc":"2.0","id":2,"method":"certificates.validate","params":{"certificateId":"sha1:..."}}
```

Its result contains `valid` and the ISO 8601 `checkedAt` time.
`certificates.sign` accepts a certificate id, base64 document bytes and signing
options. Set `checkCertificate` to make CryptoPro reject signing when the
certificate chain is not valid:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "certificates.sign",
  "params": {
    "certificateId": "store:1",
    "data": "SGVsbG8=",
    "options": {"algorithm": "gost3410-2012-256", "detached": true, "checkCertificate": true}
  }
}
```

The result contains a base64 CMS signature. Requests require
`Authorization: Bearer <token>`. Browser preflight is accepted only for an
origin listed in `allowedOrigins`. The default request limit is 16 MiB and can
be changed with `maxBodyBytes`.
