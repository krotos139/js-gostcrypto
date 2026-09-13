import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import vm from "node:vm";
import test from "node:test";

test("aggregate package loads through CommonJS require",()=>{const require=createRequire(import.meta.url),library=require("@gostcrypto/gostcrypto");assert.equal(typeof library.hash.streebog256,"function");assert.equal(typeof library.providers.PfxCertificateProvider,"function");});
test("browser ESM bundle is self-contained",async()=>{const library=await import("../dist/browser.js");assert.equal(typeof library.cms.signCms,"function");assert.equal(library.hash.streebog256(new Uint8Array()).length,32);});
test("browser IIFE exposes GostCrypto global",async()=>{const source=await readFile(new URL("../dist/gostcrypto.min.js",import.meta.url),"utf8"),context={Uint8Array,BigInt,TextEncoder,TextDecoder,Date,Map,Set,Array,Object,Math,Number,String,Error,RangeError,TypeError};vm.createContext(context);vm.runInContext(source,context);assert.equal(typeof context.GostCrypto.signature.createPrivateKey,"function");assert.equal(typeof context.GostCrypto.providers.BridgeCertificateProvider,"function");});
