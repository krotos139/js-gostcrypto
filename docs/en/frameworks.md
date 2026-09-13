# Framework examples

The repository contains runnable examples rather than framework-specific
copies of the cryptographic code:

| Example | Demonstrates |
|---|---|
| `examples/node` | File hashing and detached CMS signing with a PFX file |
| `examples/react` | Hooks, certificate selection, CryptoPro signing, and JS verification |
| `examples/angularjs` | AngularJS dependency injection with a certificate provider |
| `examples/jquery` | Installing the provider API on a jQuery instance |
| `examples/cryptopro-browser` | A bundler-free browser page using the aggregate IIFE bundle |

Complete commands are in the repository's
[examples directory](https://github.com/krotos139/js-gostcrypto/tree/main/examples).

## React

```sh
npm install @gostcrypto/asn1 @gostcrypto/cms @gostcrypto/providers @gostcrypto/react react react-dom
```

Wrap the application in `GostCryptoProvider`; use `useCertificates` and
`useGostSign` in client components. CryptoPro must be initialized in the
browser, not during server rendering.

## Node.js

```sh
npm install @gostcrypto/hash @gostcrypto/node @gostcrypto/cms
```

Node.js can hash files, open password-protected PFX containers, use the Windows
CryptoPro certificate store, or expose a restricted local signing bridge.

## Angular and AngularJS

AngularJS applications can use `@gostcrypto/angularjs`. Modern Angular does
not require a dedicated adapter: import the ESM packages in a service and
provide a `CertificateProvider` through Angular dependency injection.

## jQuery and other applications

`@gostcrypto/jquery` attaches the provider operations to a chosen jQuery
instance. Vanilla JavaScript, Vue, Svelte, Solid, and other bundlers can use
the same ESM packages and `CertificateProvider` interface directly.
