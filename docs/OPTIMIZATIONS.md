# Optimization parity with go-gostcrypto

This document records the audit against the working tree of
`go-gostcrypto`. It distinguishes portable algorithmic optimizations from
Go-specific machine-word and side-channel properties.

| Area | Go implementation | TypeScript implementation | Status |
|---|---|---|---|
| Streebog | Eight 256-entry LPS tables over eight `uint64` words; stack-local state | Eight tables split into low/high `Uint32` halves; fused XOR+LPS and four reused scratch arrays | Language-optimized equivalent |
| Kuznyechik encryption | Sixteen 256-entry fused LS tables | Sixteen 256-entry fused LS tables over four 32-bit words | Equivalent |
| Kuznyechik decryption | Fused `L^-1 S^-1`, transformed middle round keys | Same rewritten inverse round scheme and transformed keys | Equivalent |
| Kuznyechik table setup | Derive 256 entries from eight linear basis vectors | Same basis-vector construction | Equivalent |
| Kuznyechik key expansion | GF multiplication table and in-place `R`; transformed decryption keys | Module-cached iteration constants, GF table, in-place `R`, fused `L^-1`, and three reused Feistel buffers | Equivalent, with standard constants cached |
| Magma | Four 256-entry byte tables and expanded round keys | Same table layout and expanded `Uint32Array` keys | Equivalent |
| GOST 28147-89 | Four 256-entry tables reusable across `SetKey` | Tables are built once per cipher and `setKey()` reuses them | Equivalent API behavior |
| MGM | Four-bit GF window over machine words | Four-bit GF window over 32-bit words; work arrays reused per tag | Equivalent algorithmic optimization |
| GOST 34.10 arbitrary point | Projective coordinates and fixed 4-bit window | Jacobian coordinates and fixed 4-bit window | Language-optimized equivalent |
| GOST 34.10 generator | Cached 6-bit comb table | Cached 6-bit comb table per curve | Equivalent |

## Streebog implementation provenance

The TypeScript implementation is not copied from `node-gost-crypto`. Its
constants and lookup tables are generated from the formulas in the standard,
and its byte order and streaming state follow `go-gostcrypto`. The first port
used the direct S/P/L formula with `BigInt`; the Go/Python audit then replaced
that hot path with eight generated LPS tables split into 32-bit halves.

An initial optimization pass still performed XOR in a separate dynamic byte
loop before every LPS call. Comparing profiles with `node-gost-crypto` exposed
that remaining overhead: its `XLPS` helper combines the two operations. The
current implementation independently applies the same general optimization,
but retains this project's generated tables and streaming design. It performs
XOR while selecting LPS entries, so it does not create or fill a separate
64-byte intermediate buffer.

A literal Python port would regress performance: Python's `_xor` creates a new
`bytes` value and `_lps` builds a list of eight words followed by `join`. A
literal Go port is also unsuitable because JavaScript has no native `uint64`;
using `BigInt` in the compression loop is much slower. Two `Uint32` halves per
64-bit table value preserve the portable Go table strategy without either
penalty. No lookup tables were copied from a compared JavaScript project.

The Go field backend additionally uses fixed 64-bit limbs, CIOS Montgomery
multiplication, full Renes-Costello-Batina formulas, constant-time table
selection and conditional moves. Those properties cannot be reproduced by
pure JavaScript `BigInt`: engines use opaque variable-time arithmetic and do
not expose an exact 64x64-to-128-bit integer primitive. A literal BigInt port
was measured and rejected because it made signing and verification slower
without becoming constant-time. Applications requiring that threat model
must keep private-key operations in CryptoPro CSP/a hardware token through
`CertificateProvider`, or use a separately audited native/WASM backend.

## Kuznyechik key expansion

The initial TypeScript port applied the fused LS tables to encryption and the
Feistel part of key expansion, but still regenerated all 32 standard iteration
constants and transformed eight decryption keys through the bit-at-a-time GF
multiplier for every cipher instance. That path performed 81,920 inner GF loop
iterations and created more than a thousand typed-array objects and views per
key.

The current implementation follows the Go lookup strategy throughout the key
schedule. It builds the coefficient multiplication table once, performs `R`
and `R^-1` in place, caches the key-independent iteration constants, obtains
pure `L^-1` from the fused decryption table, and rotates three buffers through
the Feistel rounds. On the reference machine this reduced the warm constructor
median from roughly 497 us to 7-9 us without changing the standard ciphertexts.

Run `npm run benchmark` to measure the optimized paths on the current engine.
Correctness is covered by the RFC vectors and cross-package tests run by
`npm test`; release package metadata and exports are checked by
`npm run validate:packages`.
