# AngularJS example

The example registers a CryptoPro certificate provider as the `gostCrypto`
AngularJS constant, lists GOST certificates, signs text, and verifies the CMS
signature in JavaScript.

```sh
npm install
npm run dev
```

Modern Angular can use the same provider directly from an injectable service;
only AngularJS 1.x needs this small adapter.
