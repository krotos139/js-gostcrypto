# JavaScript implementation comparison

This project includes a reproducible, same-process comparison instead of
copying benchmark numbers reported on unrelated machines.

## Comparable implementations

The following JavaScript/TypeScript projects implement an overlapping part of
the GOST family:

| Project                                                                                          | Runtime and scope                                                                     | Included in this benchmark                                                        |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| [@li0ard/gost](https://github.com/li0ard/gost)                                                   | Modern pure TypeScript implementation of hashes, ciphers, modes, signatures, and KDFs | Yes, version 0.2.4                                                                |
| [node-gost-crypto](https://github.com/myadzel/node-gost-crypto)                                  | Node.js port of the WebCrypto GOST engine and PKI interfaces                          | Yes, version 1.0.2                                                                |
| [WebCrypto GOST](https://github.com/rudonick/crypto)                                             | Original pure-JavaScript WebCrypto and PKI implementation                             | No; `node-gost-crypto` provides its engine in a directly runnable Node.js package |
| [@wavesenterprise/crypto-gost-js](https://www.npmjs.com/package/@wavesenterprise/crypto-gost-js) | Browser-oriented fork/package of the WebCrypto GOST implementation                    | No; it has the same implementation lineage as WebCrypto GOST                      |
| [gost-crypto](https://github.com/ekorzun/gost-crypto)                                            | Older npm-packaged GOST cryptography implementation                                   | No; retained here as a reference for users evaluating legacy integrations         |

The numeric comparison covers every row in the core comparison table used by
`go-gostcrypto`: both Streebog variants, both 2015 block ciphers, Kuznyechik
key setup, and GOST R 34.10 sign/verify at 256 and 512 bits. The broader
feature sets are not equivalent: `js-gostcrypto` additionally tests CMS,
CAdES, PKCS containers, certificate providers, ACPKM, MGM, VKO, and legacy
compatibility separately.

## Reproduce the comparison

```sh
npm ci
npm run benchmark:compare
```

Set `BENCHMARK_SAMPLES` to change the sample count:

```sh
BENCHMARK_SAMPLES=9 npm run benchmark:compare
```

In PowerShell:

```powershell
$env:BENCHMARK_SAMPLES = "9"
npm run benchmark:compare
```

Before collecting timings, the script cross-checks Streebog-256 and
Streebog-512 results, the Kuznyechik and Magma standard ciphertexts, public
keys, and deterministic 256/512-bit signatures. It also asks each library to
verify both signatures. Signature encodings and digest byte order are
normalized at the adapter boundary.

Hash measurements process 8 KiB, as in the Go and Python repositories. Block
measurements reuse keyed cipher objects where the public API permits it, and
the key-setup row constructs a fresh object. One untimed warm-up is followed
by five samples; the table reports the median. All three libraries execute in
the same Node.js process.

`node-gost-crypto` exposes an unkeyed cipher object, so its block call expands
the supplied key and its key-setup row necessarily includes the first block.
Its signing API hashes its input internally, so those sign/verify figures also
include Streebog over a 32-byte message. The other two APIs accept a prepared
digest. These small API differences are disclosed rather than bypassed through
private internals.

## Reference run

Recorded on 2026-09-13 with Node.js 22.14.0 for Windows x64 on an Intel Core
i7-9700K at 3.60 GHz:

| Operation | js-gostcrypto | @li0ard/gost 0.2.4 | node-gost-crypto 1.0.2 |
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

¹ Includes key expansion because of the public `node-gost-crypto` API.
² Includes hashing a 32-byte message because of the public
`node-gost-crypto` API.

The earlier 5.93 MB/s Streebog-256 result exposed an incomplete hot-loop
optimization: XOR and LPS still ran as two byte passes. Fusing them raised the
same implementation to 11.48 MB/s in this run, slightly ahead of
`node-gost-crypto`; Streebog-512 now has comparable throughput as well. The
change and its relationship to the Go, Python, and other JavaScript designs
are recorded in [OPTIMIZATIONS.md](OPTIMIZATIONS.md).

These numbers are observations, not permanent guarantees: JIT version, CPU,
power management, input size, and surrounding load can change the result.

## What is and is not measured

- The benchmark measures warm public-API calls, including normal output
  allocation and dispatch.
- It does not measure module startup, bundle size, memory consumption, browser
  engines, worker concurrency, or provider/CSP calls.
- It does not imply constant-time behavior or side-channel resistance.
- CryptoPro and USB-token signing is intentionally excluded: token hardware,
  PIN state, certificate checks, and CSP configuration dominate those timings.
- Use `npm run benchmark` for the wider project-only suite, including MGM.

The implementation techniques inherited from the Go project and the remaining
JavaScript runtime limitations are documented in
[OPTIMIZATIONS.md](OPTIMIZATIONS.md).
