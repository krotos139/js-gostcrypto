import assert from "node:assert/strict";
import test from "node:test";
import * as gostcrypto from "@gostcrypto/gostcrypto";

test("aggregate package exposes every public module",()=>{assert.deepEqual(Object.keys(gostcrypto).sort(),["acpkm","asn1","ciphers","cms","core","gost28147","gost341194","hash","kdf","keywrap","mgm","modes","pfx","pkcs8","providers","signature","vko"]);assert.equal(gostcrypto.hash.streebog256(new Uint8Array()).length,32);assert.equal(typeof gostcrypto.cms.signCms,"function");assert.equal(typeof gostcrypto.pfx.parsePfx,"function");assert.equal(typeof gostcrypto.providers.PfxCertificateProvider,"function");});
