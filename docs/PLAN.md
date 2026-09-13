# Implementation plan

The implementation ports the full capability set of `go-gostcrypto` in this
order: core and hash; ciphers and GOST 34.13 modes; KDF/MGM/ACPKM/key wrap;
GOST 34.10; ASN.1/PKI and PKCS#8/PFX; CMS/CAdES; legacy readers.

Implemented: core contracts, Streebog-256/512, Magma, Kuznyechik, all six
GOST 34.13 modes and padding procedures, OMAC1, HMAC-Streebog, KDF, KDF_TREE,
PBKDF2, VKO, MGM, ACPKM and ACPKM-Master modes, KExp15/KImp15, GOST R 34.10-2012 with all named
curves, PKIX public-key encoding, certificate-signature verification and
plain/masked/encrypted PKCS#8 PrivateKeyInfo, legacy GOST 28147-89 with
CryptoPro key meshing, GOST R 34.11-94, verification of PKCS#10 requests and
certificate revocation lists, CMS SignedData, CAdES-BES/CAdES-T, RFC 3161,
RFC 4490 EnvelopedData, password- and key-protected PFX, RFC 4357 key wrap,
certificate providers with native trust validation, direct CryptoPro browser plug-in integration,
CryptoPro Windows system-store provider, authenticated browser/Node.js JSON-RPC bridge and
its TLS-first command-line launcher,
multi-runtime bundles and framework integrations. Performance work includes
the Go implementation's fused tables for Streebog, Kuznyechik, Magma and
GOST 28147, fused inverse Kuznyechik rounds, bounded-memory streaming,
windowed MGM field multiplication, projective curve coordinates,
fixed-window scalar multiplication and a cached generator comb table. The
complete audit is recorded in `docs/OPTIMIZATIONS.md`.

Interoperability coverage includes RFC/standard fixtures and deterministic
Streebog-256/512 and GOST R 34.11-94 fixtures produced by CryptoPro CSP 5.0. The optional
`npm run interop:cryptopro` command repeats the comparison against an installed
`csptest.exe` using CMS `DigestedData` output.

The planned porting scope is complete. Independent coverage includes published
RFC/standard fixtures, deterministic outputs from CryptoPro CSP 5.0, and a
manual end-to-end browser test that creates CAdES-BES with the CryptoPro
extension/hardware token and verifies the result in this implementation.
Private-key operations that require stronger side-channel guarantees are
delegated to the native CSP or token through `CertificateProvider`; pure
JavaScript does not claim constant-time behavior. A WASM implementation is not
bundled merely to provide a second unaudited implementation of the same code.

Every package has ESM, declarations, an `exports` map and an explicit npm
`files` list. The aggregate package additionally ships self-contained CommonJS,
browser ESM and browser IIFE builds. Browser, Node.js, React, AngularJS, jQuery
and vanilla JS use the same core; framework integrations are optional wrappers.

The certificate-store feature is implemented behind `CertificateProvider`.
Pure browser JavaScript never receives a private key from the system store.
Applications can use either the CryptoPro browser plug-in directly or the
authenticated local Node.js agent backed by Windows CAdESCOM. Both paths expose
explicit certificate trust validation; signing can optionally require a valid
chain.
