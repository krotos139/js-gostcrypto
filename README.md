# gostcrypto-js

[English](README.md) | [Русский](README.ru.md)

A TypeScript port of [go-gostcrypto](https://github.com/krotos139/go-gostcrypto).
The published artifacts are ordinary JavaScript with TypeScript declarations
and can be consumed from Node.js, browsers, React, AngularJS, jQuery, and modern
bundlers.

The planned porting scope is complete. RFC and GOST vectors from the Go project
are retained as compatibility tests, and the implementation includes the Go
version's portable lookup-table, block-processing, and elliptic-curve
optimizations. See the [optimization audit](docs/OPTIMIZATIONS.md).

> This project is not a certified cryptographic protection tool. Browser code
> cannot read private keys directly from an operating-system or USB-token
> store; signing is delegated to CryptoPro or an authenticated local provider.

## Related projects

- [gostcryptkit](https://github.com/krotos139/gostcryptkit) — the related
  cryptographic toolkit;
- [go-gostcrypto](https://github.com/krotos139/go-gostcrypto) — the Go
  implementation and source of the ported algorithms and test vectors.

## Implemented algorithms and formats

| Standard | Implementation |
|---|---|
| GOST R 34.12-2015 | Magma and Kuznyechik block ciphers |
| GOST R 34.13-2015 | ECB, CTR, CBC, OFB, CFB, padding, and OMAC |
| GOST R 34.11-2012 | Streaming Streebog-256 and Streebog-512 |
| GOST R 34.10-2012 | TC26 curves, signatures, key codecs, and VKO-2012 |
| RFC 7836 / R 1323565.1.017-2018 | KDF, KDF_TREE, CTR-ACPKM, ACPKM-Master, KExp15/KImp15 |
| RFC 9058 / RFC 9059 | MGM authenticated encryption |
| Legacy standards | GOST 28147-89, GOST R 34.11-94, CryptoPro key wrap |
| PKI and containers | DER/ASN.1, PKIX, PKCS#8/#10/#12, certificates, CRLs, CMS, CAdES-BES/T, RFC 3161, RFC 4490 |
| Certificate access | PFX, CryptoPro browser plug-in, Windows CAdESCOM, authenticated HTTP bridge |

The workspace is split into focused `@gostcrypto/*` packages. The most commonly
used packages are:

| Package                                                                       | Purpose                                                         |
| ----------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `@gostcrypto/gostcrypto`                                                      | Aggregate ESM, CommonJS, browser ESM, and browser IIFE builds   |
| `@gostcrypto/hash`, `@gostcrypto/ciphers`, `@gostcrypto/modes`                | Low-level primitives                                            |
| `@gostcrypto/signature`, `@gostcrypto/vko`                                    | Signatures and key agreement                                    |
| `@gostcrypto/asn1`, `@gostcrypto/pkcs8`, `@gostcrypto/pfx`, `@gostcrypto/cms` | Keys, certificates, containers, and documents                   |
| `@gostcrypto/providers`                                                       | PFX, browser plug-in, and bridge providers                      |
| `@gostcrypto/node`                                                            | Node.js PFX access, CryptoPro store integration, and bridge CLI |
| `@gostcrypto/react`, `@gostcrypto/angularjs`, `@gostcrypto/jquery`            | Optional framework adapters                                     |

## Installation

Install the aggregate package when an application needs several algorithms or
formats:

```sh
npm install @gostcrypto/gostcrypto
```

ES modules and bundlers:

```js
import { hash, cms, providers } from "@gostcrypto/gostcrypto";

const digest = hash.streebog256(new TextEncoder().encode("hello"));
```

CommonJS in Node.js:

```js
const { hash, cms } = require("@gostcrypto/gostcrypto");
```

A plain browser can load the package's `dist/gostcrypto.min.js` file and use
the global `GostCrypto` object.

## React, Node.js, AngularJS, and jQuery

No additional packaging work is required. Every package has an `exports` map,
`.d.ts` declarations, a restricted `files` list, and tree-shaking metadata.
React, AngularJS, and jQuery are peer dependencies of their adapters, so an
application keeps control of its framework version.

Install only the adapter needed by the application:

```sh
# React
npm install @gostcrypto/gostcrypto @gostcrypto/providers @gostcrypto/react

# Node.js and the optional certificate bridge executable
npm install @gostcrypto/gostcrypto @gostcrypto/node

# AngularJS or jQuery
npm install @gostcrypto/gostcrypto @gostcrypto/angularjs
npm install @gostcrypto/gostcrypto @gostcrypto/jquery
```

React example:

```jsx
import {
  GostCryptoProvider,
  useCertificates,
  useGostSign,
} from "@gostcrypto/react";
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

const provider = createCryptoProBrowserProvider();

export function App() {
  return (
    <GostCryptoProvider provider={provider}>
      <Signer />
    </GostCryptoProvider>
  );
}

function Signer() {
  const { certificates } = useCertificates();
  const sign = useGostSign();
  // Call sign(certificateId, Uint8Array, options) from an event handler.
  return <div>{certificates.length} certificate(s)</div>;
}
```

Node.js can open a PFX directly:

```js
import { openPfxFile } from "@gostcrypto/node";

const provider = await openPfxFile("signing-key.pfx", "password");
```

Node.js 18 needs `NODE_OPTIONS=--experimental-global-webcrypto` for operations
that generate random keys, nonces, salts, or content-encryption keys. Node.js
20 and newer expose the required Web Crypto generator by default.

See the [runtime and framework guide](docs/INTEGRATIONS.md) for complete setup
notes.

## Browser certificates and USB tokens

When the official CryptoPro browser extension and `cadesplugin_api.js` are
available, JavaScript can list certificates, validate a chain, and ask the CSP
or USB token to create a CAdES signature. The private key never enters the JS
heap.

```js
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

const provider = createCryptoProBrowserProvider();
const certificates = await provider.listCertificates();
const signature = await provider.sign(certificates[0].id, documentBytes, {
  algorithm: "gost3410-2012-256",
  detached: true,
  checkCertificate: true,
});
```

Run the included interactive page with `npm run test:browser:cryptopro`. It
lists certificates and can create and verify a signature using the selected
certificate. If direct plug-in access is unavailable, use the authenticated
Node.js bridge described in [the native bridge guide](docs/NATIVE_BRIDGE.md).

## Performance

Measured on September 13, 2026, with Node.js 22.14.0 for Windows x64 on an
Intel Core i7-9700K at 3.60 GHz. Each value is the median of five samples.
All implementations used the same inputs and curves; hashes, blocks, public
keys, normalized deterministic signatures, and verification results were
cross-checked before timing.

| Operation | gostcrypto-js | @li0ard/gost 0.2.4 | node-gost-crypto 1.0.2 |
|---|---:|---:|---:|
| Streebog-256, 8 KiB | **11.48 MB/s** | 0.24 MB/s | 9.70 MB/s |
| Streebog-512, 8 KiB | 10.76 MB/s | 0.20 MB/s | **10.86 MB/s** |
| Kuznyechik, one block | **1.0 us** | 84.2 us | 81.8 us¹ |
| Magma, one block | **181 ns** | 2.4 us | 1.5 us¹ |
| Kuznyechik key setup | 718.8 us | 386.0 us | **83.7 us¹** |
| Sign, 256 bit | **511.9 us** | 1.30 ms | 1.29 ms² |
| Verify, 256 bit | **4.77 ms** | 6.54 ms | 9.92 ms² |
| Sign, 512 bit | **1.06 ms** | 3.79 ms | 2.05 ms² |
| Verify, 512 bit | **19.71 ms** | 26.26 ms | 51.01 ms² |

¹ The public `node-gost-crypto` cipher API expands the key on every block.
² Its public signature API also hashes the 32-byte input.

Run the project-only benchmark:

```sh
npm run benchmark
```

Run the reproducible comparison with `@li0ard/gost` and `node-gost-crypto`:

```sh
npm run benchmark:compare
```

The comparison includes every operation in the core comparison table from
`go-gostcrypto`. Results, methodology, API caveats, the Streebog optimization
analysis, and links to other JavaScript implementations are in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Development and CI

```sh
npm ci
npm run validate:packages
npm test
npm pack --workspaces --dry-run
```

GitHub Actions tests Node.js 18, 20, and 22 on Linux, runs a Windows smoke test,
validates package manifests and tarballs, and executes the comparison benchmark
as a correctness smoke test. Tagged `v*` releases use the separate npm release
workflow with provenance.

## Security

JavaScript `BigInt` operations and JIT compilation are not constant-time, and
lookup-table indices depend on processed data. Applications whose threat model
includes hostile local code should keep private-key operations in an audited
CSP, hardware token, or native agent and use `CertificateProvider` only as the
boundary.

For CryptoPro interoperability checks on Windows, run
`npm run interop:cryptopro`. It compares deterministic Streebog-256/512 and
GOST R 34.11-94 output with an installed `csptest.exe`.

## License

MIT. See [LICENSE](LICENSE) for the full text.

Copyright (c) 2026 IURII IAKOVLEV
