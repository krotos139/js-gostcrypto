# Getting started

`gostcrypto-js` provides GOST algorithms, key and certificate formats, CMS,
and certificate-provider adapters as small `@gostcrypto/*` npm packages. The
same TypeScript declarations and JavaScript implementations work in Node.js,
modern browsers, and common frontend build tools.

## Install

Use the aggregate package when an application needs several features:

```sh
npm install @gostcrypto/gostcrypto
```

```js
import { hash } from "@gostcrypto/gostcrypto";

const data = new TextEncoder().encode("hello");
const digest = hash.streebog256(data);
```

Focused packages such as `@gostcrypto/hash`, `@gostcrypto/ciphers`, and
`@gostcrypto/cms` avoid pulling unrelated APIs into an application.

## Environments

- ESM is available from every package.
- The aggregate package also exposes CommonJS and browser bundles.
- Every package includes TypeScript declarations and package export maps.
- React, AngularJS, and jQuery integrations are optional adapters.

See [framework examples](frameworks.md) for complete runnable projects and
[certificates and USB tokens](certificates.md) before adding browser signing.

## Development

```sh
npm ci
npm test
npm run validate:examples
```

The implementation follows the algorithms and test vectors from
[go-gostcrypto](https://github.com/krotos139/go-gostcrypto). Benchmark and
optimization details are available in the
[benchmark report](../BENCHMARKS.md) and [optimization audit](../OPTIMIZATIONS.md).
