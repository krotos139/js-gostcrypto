# Runtime and framework integration

The core packages contain no framework-specific global state. Framework
packages are small adapters around the same `CertificateProvider` contract,
so cryptographic behavior does not change between React, Node.js, AngularJS,
jQuery, and vanilla browser code.

Runnable projects for all of these environments are available in the
[examples directory](https://github.com/krotos139/js-gostcrypto/tree/main/examples).

## Package readiness

The npm metadata needed by consumers is already present:

| Capability                      | Status                                                                                           |
| ------------------------------- | ------------------------------------------------------------------------------------------------ |
| ESM entry points                | All packages expose `dist/index.js`                                                              |
| CommonJS                        | The aggregate `@gostcrypto/gostcrypto` package exposes `dist/index.cjs`                          |
| Browser bundlers                | The aggregate package has a browser export and `browser` field                                   |
| Plain `<script>` use            | `@gostcrypto/gostcrypto/global` exposes the `GostCrypto` IIFE bundle                             |
| TypeScript                      | Every package publishes `dist/index.d.ts`                                                        |
| Tree shaking                    | Packages declare `sideEffects: false`                                                            |
| React/AngularJS/jQuery versions | Frameworks are peer dependencies of their adapters                                               |
| Node.js compatibility           | `@gostcrypto/node` declares Node.js 18 or newer                                                  |
| CLI installation                | `@gostcrypto/node` publishes the `gostcrypto-bridge` executable                                  |
| Package contents                | `files` restricts publication to built artifacts; license and README are copied during the build |

No extra React component library, Angular module format, or Node-specific copy
of the algorithms is needed. The remaining distribution step is publishing the
workspace packages to npm with the existing release workflow.

## React

```sh
npm install @gostcrypto/gostcrypto @gostcrypto/providers @gostcrypto/react
```

`@gostcrypto/react` declares React 18 or newer as a peer dependency and exports
`GostCryptoProvider`, `useCertificateProvider`, `useCertificates`, and
`useGostSign`.

```jsx
import { GostCryptoProvider, useCertificates } from "@gostcrypto/react";
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

const certificateProvider = createCryptoProBrowserProvider();

function CertificateList() {
  const { certificates, loading, error, refresh } = useCertificates();
  if (loading) return <p>Loading…</p>;
  if (error) return <button onClick={refresh}>Retry</button>;
  return (
    <ul>
      {certificates.map((item) => (
        <li key={item.id}>{item.subject}</li>
      ))}
    </ul>
  );
}

export function App() {
  return (
    <GostCryptoProvider provider={certificateProvider}>
      <CertificateList />
    </GostCryptoProvider>
  );
}
```

The adapter works with Vite, Webpack, Next.js client components, and other
React-aware bundlers. CryptoPro browser APIs must only be initialized on the
client, because they depend on the browser extension.

## Node.js

```sh
npm install @gostcrypto/gostcrypto @gostcrypto/node
```

The aggregate algorithms support both ESM imports and CommonJS `require`.
Node-specific PFX, Windows certificate-store, and bridge functionality uses
ESM:

```js
import {
  createCertificateBridgeServer,
  createCryptoProCertificateProvider,
  openPfxFile,
} from "@gostcrypto/node";

const pfxProvider = await openPfxFile("certificate.pfx", "password");

const windowsProvider = createCryptoProCertificateProvider();
createCertificateBridgeServer(windowsProvider, {
  bearerToken: process.env.BRIDGE_TOKEN,
  allowedOrigins: ["https://documents.example"],
}).listen(19443, "127.0.0.1");
```

Node.js 20 and newer expose the required Web Crypto random generator by
default. On Node.js 18, start the process with
`NODE_OPTIONS=--experimental-global-webcrypto` before calling operations that
generate keys, nonces, salts, or content-encryption keys. Deterministic
operations such as hashing and verification do not need that flag.

Use TLS, a high-entropy bearer token, an explicit origin allowlist, and a
loopback bind for the bridge. Full operational details are in
[NATIVE_BRIDGE.md](NATIVE_BRIDGE.md).

## AngularJS

```sh
npm install @gostcrypto/gostcrypto @gostcrypto/angularjs
```

```js
import angular from "angular";
import { registerGostCryptoModule } from "@gostcrypto/angularjs";
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

registerGostCryptoModule(angular, createCryptoProBrowserProvider());
```

The adapter supports AngularJS 1.6 or newer. Modern Angular does not need a
dedicated adapter; import the ESM packages in a service and provide the
`CertificateProvider` through Angular dependency injection.

## jQuery

```sh
npm install @gostcrypto/gostcrypto @gostcrypto/jquery
```

```js
import $ from "jquery";
import { installGostCrypto } from "@gostcrypto/jquery";
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

installGostCrypto($, createCryptoProBrowserProvider());
```

The adapter supports jQuery 3 or newer and attaches the provider operations to
the configured jQuery instance rather than assuming a global `$`.

## Browser certificate providers

Choose one provider boundary:

1. `createCryptoProBrowserProvider()` calls the official CryptoPro extension
   through `cadesplugin_api.js` and is the shortest path to a USB token.
2. `createHttpCertificateProvider()` calls the authenticated local bridge and
   works when direct extension integration is unsuitable.
3. `PfxCertificateProvider` handles an explicitly supplied PFX container in
   JavaScript; use it only when placing key material in the JS process is
   acceptable for the application's threat model.

Browsers do not expose arbitrary OS certificate stores or PKCS#11 tokens
through standard WebCrypto. A vendor extension, native agent, or server-side
signing boundary is therefore required for non-exportable keys.
