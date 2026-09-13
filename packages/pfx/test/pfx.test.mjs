import assert from "node:assert/strict";
import test from "node:test";
import { publicKeyFromCertificate } from "@gostcrypto/asn1";
import { marshalPfx, parsePfx, PfxError } from "@gostcrypto/pfx";
import { createPrivateKey, TC26_PARAM_SET_256_B } from "@gostcrypto/signature";

const password=new TextEncoder().encode("Пароль для PFX");
const example=Uint8Array.from(Buffer.from(`MIIFqgIBAzCCBSsGCSqGSIb3DQEHAaCCBRwEggUYMIIFFDCCASIGCSqGSIb3DQEH
AaCCARMEggEPMIIBCzCCAQcGCyqGSIb3DQEMCgECoIHgMIHdMHEGCSqGSIb3DQEF
DTBkMEEGCSqGSIb3DQEFDDA0BCD5qZr0TTIsBvdgUoq/zFwOzdyJohj6/4Wiyccg
j9AK/QICB9AwDAYIKoUDBwEBBAIFADAfBgYqhQMCAhUwFQQI3Ip/Vp0IsyIGCSqF
AwcBAgUBAQRoSfLhgx9s/zn+BjnhT0ror07vS55Ys5hgvVpWDx4mXGWWyez/2sMc
aFgSr4H4UTGGwoMynGLpF1IOVo+bGJ0ePqHB+gS5OL9oV+PUmZ/ELrRENKlCDqfY
WvpSystX29CvCFrnTnDsbBYxFTATBgkqhkiG9w0BCRUxBgQEAQAAADCCA+oGCSqG
SIb3DQEHBqCCA9swggPXAgEAMIID0AYJKoZIhvcNAQcBMHEGCSqGSIb3DQEFDTBk
MEEGCSqGSIb3DQEFDDA0BCCJTJLZQRi1WIpQHzyjXbq7+Vw2+1280C45x8ff6kMS
VAICB9AwDAYIKoUDBwEBBAIFADAfBgYqhQMCAhUwFQQIxepowwvS11MGCSqFAwcB
AgUBAYCCA06n09P/o+eDEKoSWpvlpOLKs7dKmVquKzJ81nCngvLQ5fEWL1WkxwiI
rEhm53JKLD0wy4hekalEk011Bvc51XP9gkDkmaoBpnV/TyKIY35wl6ATfeGXno1M
KoA+Ktdhv4gLnz0k2SXdkUj11JwYskXue+REA0p4m2ZsoaTmvoODamh9JeY/5Qjy
Xe58CGnyXFzX3eU86qs4WfdWdS3NzYYOk9zzVl46le9u79O/LnW2j4n2of/Jpk/L
YjrRmz5oYeQOqKOKhEyhpO6e+ejr6laduEv7TwJQKRNiygogbVvkNn3VjHTSOUG4
W+3NRPhjb0jD9obdyx6MWa6O3B9bUzFMNav8/gYn0vTDxqXMLy/92oTngNrVx6Gc
cNl128ISrDS6+RxtAMiEBRK6xNkemqX5yNXG5GrLQQFGP6mbs2nNpjKlgj3pljmX
Eky2/G78XiJrv02OgGs6CKnI9nMpa6N7PBHV34MJ6EZzWOWDRQ420xk63mnicrs0
WDVJ0xjdu4FW3iEk02EaiRTvGBpa6GL7LBp6QlaXSSwONx725cyRsL9cTlukqXER
WHDlMpjYLbkGZRrCc1myWgEfsputfSIPNF/oLv9kJNWacP3uuDOfecg3us7eg2OA
xo5zrYfn39GcBMF1WHAYRO/+PnJb9jrDuLAE8+ONNqjNulWNK9CStEhb6Te+yE6q
oeP6hJjFLi+nFLE9ymIo0A7gLQD5vzFvl+7v1ZNVnQkwRUsWoRiEVVGnv3Z1iZU6
xStxgoHMl62V/P5cz4dr9vJM2adEWNZcVXl6mk1H8DRc1sRGnvs2l237oKWRVntJ
hoWnZ8qtD+3ZUqsX79QhVzUQBzKuBt6jwNhaHLGl5B+Or/zA9FezsOh6+Uc+fZaV
W7fFfeUyWwGy90XD3ybTrjzep9f3nt55Z2c+fu2iEwhoyImWLuC3+CVhf9Af59j9
8/BophMJuATDJEtgi8rt4vLnfxKu250Mv2ZpbfF69EGTgFYbwc55zRfaUG9zlyCu
1YwMJ6HC9FUVtJp9gObSrirbzTH7mVaMjQkBLotazWbegzI+be8V3yT06C+ehD+2
GdLWAVs9hp8gPHEUShb/XrgPpDSJmFlOiyeOFBO/j4edDACKqVcwdjBOMAoGCCqF
AwcBAQIDBEAIFX0fyZe20QKKhWm6WYX+S92Gt6zaXroXOvAmayzLfZ5Sd9C2t9zZ
JSg6M8RBUYpw/8ym5ou1o2nDa09M5zF3BCCpzyCQBI+rzfISeKvPV1ROfcXiYU93
mwcl1xQV2G5/fgICB9A=`,"base64"));
const certificate=Uint8Array.from(Buffer.from(`MIIDAjCCAq2gAwIBAgIQAdBoXzEflsAAAAALJwkAATAMBggqhQMHAQEDAgUAMGAx
CzAJBgNVBAYTAlJVMRUwEwYDVQQHDAzQnNC+0YHQutCy0LAxDzANBgNVBAoMBtCi
0JoyNjEpMCcGA1UEAwwgQ0EgY2VydGlmaWNhdGUgKFBLQ1MjMTIgZXhhbXBsZSkw
HhcNMTUwMzI3MDcyNTAwWhcNMjAwMzI3MDcyMzAwWjBkMQswCQYDVQQGEwJSVTEV
MBMGA1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQKDAbQotCaMjYxLTArBgNVBAMM
JFRlc3QgY2VydGlmaWNhdGUgMSAoUEtDUyMxMiBleGFtcGxlKTBmMB8GCCqFAwcB
AQEBMBMGByqFAwICIwEGCCqFAwcBAQICA0MABEDXHPKaSm+vZ1glPxZM5fcO33r/
6Eaxc3K1RCmRYHkiYkzi2D0CwLhEhTBXkfjUyEbS4FEXB5PM3oCwB0G+FMKVgQkA
MjcwOTAwMDGjggEpMIIBJTArBgNVHRAEJDAigA8yMDE1MDMyNzA3MjUwMFqBDzIw
MTYwMzI3MDcyNTAwWjAOBgNVHQ8BAf8EBAMCBPAwHQYDVR0OBBYEFCFY6xFDrzJg
3ZS2D+jAehZyqxVtMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAMBgNV
HRMBAf8EAjAAMIGZBgNVHSMEgZEwgY6AFCadzteHnKRvm38EzA6TEDh2t8SaoWSk
YjBgMQswCQYDVQQGEwJSVTEVMBMGA1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQK
DAbQotCaMjYxKTAnBgNVBAMMIENBIGNlcnRpZmljYXRlIChQS0NTIzEyIGV4YW1w
bGUpghAB0Ghe8vxNIAAAAAsnCQABMAwGCCqFAwcBAQMCBQADQQD2irRW+TySSAjC
SnTHQnl4q2Jrgw1OLAoCbuOCcJkjHc73wFOFpNfdlCESjZEv2lMI+vrAUyF54n5h
0YxF5e+y`,"base64"));

test("R 50.1.112-2016 PFX example",()=>{
  const container=parsePfx(example,password);assert.equal(container.hasMac,true);assert.equal(container.skippedSections,0);assert.equal(container.keys.length,1);assert.equal(container.certificates.length,1);assert.equal(container.keys[0].encrypted,true);assert.deepEqual(container.certificates[0].certificate,certificate);
  const publicKey=publicKeyFromCertificate(certificate);assert.equal(container.keys[0].key.publicKey.x,publicKey.x);assert.equal(container.keys[0].key.publicKey.y,publicKey.y);assert.equal(container.certificateFor(container.keys[0]),container.certificates[0]);
});

test("PFX marshal round-trips encrypted and plain certificate sections",()=>{
  const key=createPrivateKey(TC26_PARAM_SET_256_B,123456789n);let counter=0;const fill=(target)=>{for(let i=0;i<target.length;i+=1)target[i]=counter++&255;};
  for(const plainCertificates of[false,true]){const der=marshalPfx(key,[certificate],password,{iterations:2,plainCertificates,friendlyName:"Тест",fillRandom:fill});const container=parsePfx(der,password);assert.equal(container.hasMac,true);assert.equal(container.keys.length,1);assert.equal(container.keys[0].friendlyName,"Тест");assert.deepEqual(container.keys[0].key,key);assert.deepEqual(container.certificateFor(container.keys[0])?.certificate,certificate);const tampered=Uint8Array.from(der);tampered[Math.floor(tampered.length/2)]^=1;assert.throws(()=>parsePfx(tampered,password));}
});

test("PFX distinguishes a wrong password from malformed data",()=>{
  const broken=Uint8Array.from(example.subarray(0,30));assert.throws(()=>parsePfx(broken,password),(error)=>error instanceof PfxError&&error.code==="MALFORMED");
  const der=marshalPfx(createPrivateKey(TC26_PARAM_SET_256_B,2n),[],password,{iterations:2,fillRandom:(target)=>target.fill(7)});assert.throws(()=>parsePfx(der,new TextEncoder().encode("wrong")),(error)=>error instanceof PfxError&&error.code==="MAC");
});
