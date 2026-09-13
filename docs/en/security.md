# Security

This project is not a certified cryptographic product. JavaScript `BigInt`, JIT
compilation, garbage collection, and lookup-table access are not constant-time.

- Keep non-exportable private keys in a CSP, hardware token, native agent, or
  audited server-side signer.
- Treat PFX passwords and bearer tokens as secrets; never embed them in browser
  bundles or source control.
- Bind a local bridge to loopback, use TLS where appropriate, require a
  high-entropy token, and allow only explicit origins.
- Validate certificate chains and revocation status independently of checking
  the mathematical CMS signature.
- Pin dependencies and run the project test vectors on every release.

The `CertificateProvider` boundary is designed so applications can keep the
private-key operation outside the JavaScript heap.
