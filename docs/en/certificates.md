# Certificates and USB tokens

Browser JavaScript cannot read arbitrary private keys from an operating-system
store or USB token through standard WebCrypto. Use one of the provider
boundaries supplied by the library:

1. `createCryptoProBrowserProvider()` calls the official CryptoPro extension
   through `cadesplugin_api.js`.
2. `createHttpCertificateProvider()` calls an authenticated native or remote
   signing bridge.
3. `PfxCertificateProvider` operates on an explicitly supplied PFX container
   inside the JavaScript process.

With the CryptoPro provider, the private key stays in CSP or on the token:

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

Serve browser applications from `localhost` or HTTPS. Load the official
CryptoPro browser API before creating the provider. Certificate trust and CMS
signature correctness are separate checks; applications should perform both.

The bundler-free interactive test is started with:

```sh
npm run test:browser:cryptopro
```

For the local bridge threat model and deployment controls, read the
[native bridge guide](../NATIVE_BRIDGE.md).
