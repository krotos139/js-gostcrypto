# Algorithms and formats

| Standard | Implemented functionality |
|---|---|
| GOST R 34.12-2015 | Magma and Kuznyechik block ciphers |
| GOST R 34.13-2015 | ECB, CTR, CBC, OFB, CFB, padding, and OMAC |
| GOST R 34.11-2012 | Streaming Streebog-256 and Streebog-512 |
| GOST R 34.10-2012 | TC26 curves, signatures, key codecs, and VKO-2012 |
| RFC 7836 / R 1323565.1.017-2018 | KDF, KDF_TREE, CTR-ACPKM, ACPKM-Master, KExp15, and KImp15 |
| RFC 9058 / RFC 9059 | MGM authenticated encryption |
| Legacy standards | GOST 28147-89, GOST R 34.11-94, and CryptoPro key wrap |
| PKI and containers | DER/ASN.1, PKIX, PKCS #8/#10/#12, certificates, CRLs, CMS, CAdES-BES/T, RFC 3161, and RFC 4490 |

Import the narrowest package that fits the application:

```js
import { streebog512 } from "@gostcrypto/hash";
import { Kuznyechik } from "@gostcrypto/ciphers";
import { parseSignedData } from "@gostcrypto/cms";
```

The full correctness suite is derived from RFC, GOST, and upstream Go vectors.
For performance methodology and comparisons with other JavaScript
implementations, see [Benchmarks](../BENCHMARKS.md).
