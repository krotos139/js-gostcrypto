import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { createServer, type IncomingMessage, type RequestListener, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import type { CertificateInfo, CertificateProvider, CertificateValidationResult, SignOptions } from "@gostcrypto/core";
import { PfxCertificateProvider } from "@gostcrypto/providers";
export async function openPfxFile(path:string|URL,password:string|Uint8Array):Promise<PfxCertificateProvider>{const bytes=await readFile(path),encodedPassword=typeof password==="string"?new TextEncoder().encode(password):password;return PfxCertificateProvider.open(bytes,encodedPassword);}

export type CryptoProCommand =
  | { readonly operation: "list" }
  | { readonly operation: "validate"; readonly certificateId: string }
  | { readonly operation: "sign"; readonly certificateId: string; readonly data: string; readonly algorithm: SignOptions["algorithm"]; readonly detached: boolean; readonly checkCertificate: boolean };

/** Injectable command boundary, useful for policy wrappers and tests. */
export type CryptoProCommandRunner = (command: CryptoProCommand) => Promise<unknown>;

export interface CryptoProCertificateProviderOptions {
  /** Defaults to 64-bit Windows PowerShell 5.1. Set the SysWOW64 path for a 32-bit-only CSP. */
  readonly powershellPath?: string;
  readonly timeoutMilliseconds?: number;
  readonly maxOutputBytes?: number;
  readonly runner?: CryptoProCommandRunner;
}

const cryptoProPowerShell = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Release-Com([object] $value) {
  if ($null -ne $value -and [Runtime.InteropServices.Marshal]::IsComObject($value)) {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($value)
  }
}
function Normalize-Thumbprint([string] $value) {
  $withoutPrefix = $value -replace '^sha1:', ''
  return ($withoutPrefix -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
}
function Open-PersonalStore {
  $value = $null
  try {
    $value = New-Object -ComObject CAdESCOM.Store
    $value.Open(2, 'My', 0)
    return $value
  } catch {
    Release-Com $value
    # Some CryptoPro desktop installations register the signing objects but
    # expose the personal store through the compatible CAPICOM object only.
    $value = New-Object -ComObject CAPICOM.Store
    $value.Open(2, 'My', 0)
    return $value
  }
}
try {
  $requestText = [Console]::In.ReadToEnd()
  if ([String]::IsNullOrWhiteSpace($requestText)) { throw 'CryptoPro command is empty' }
  $request = $requestText | ConvertFrom-Json
  if ($request.operation -eq 'list') {
    $store = $null
    try {
      $store = Open-PersonalStore
      $certificates = $store.Certificates
      $result = @()
      for ($index = 1; $index -le $certificates.Count; $index += 1) {
        $certificate = $certificates.Item($index)
        try {
          $thumbprint = Normalize-Thumbprint ([string] $certificate.Thumbprint)
          $result += [ordered]@{
            id = 'sha1:' + $thumbprint
            subject = [string] $certificate.SubjectName
            issuer = [string] $certificate.IssuerName
            serialNumber = [string] $certificate.SerialNumber
            validFrom = ([DateTime] $certificate.ValidFromDate).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            validTo = ([DateTime] $certificate.ValidToDate).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            der = (([string] $certificate.Export(0)) -replace '\s', '')
            hasPrivateKey = [bool] $certificate.HasPrivateKey()
          }
        } finally { Release-Com $certificate }
      }
      @{ ok = $true; result = $result } | ConvertTo-Json -Compress -Depth 5
    } finally {
      if ($null -ne $store) { try { $store.Close() } catch {}; Release-Com $store }
    }
  } elseif ($request.operation -eq 'validate') {
    $store = $null
    try {
      $thumbprint = Normalize-Thumbprint ([string] $request.certificateId)
      if ([String]::IsNullOrEmpty($thumbprint)) { throw 'Certificate id must contain a SHA-1 thumbprint' }
      $store = Open-PersonalStore
      $matches = $store.Certificates.Find(0, $thumbprint)
      if ($matches.Count -ne 1) { throw "Expected one certificate with thumbprint $thumbprint, found $($matches.Count)" }
      $certificate = $matches.Item(1)
      try {
        $status = $certificate.IsValid()
        try { @{ ok = $true; result = @{ valid = [bool] $status.Result } } | ConvertTo-Json -Compress -Depth 4 }
        finally { Release-Com $status }
      } finally { Release-Com $certificate }
    } finally {
      if ($null -ne $store) { try { $store.Close() } catch {}; Release-Com $store }
    }
  } elseif ($request.operation -eq 'sign') {
    $store = $null
    $signer = $null
    $signedData = $null
    try {
      $thumbprint = Normalize-Thumbprint ([string] $request.certificateId)
      if ([String]::IsNullOrEmpty($thumbprint)) { throw 'Certificate id must contain a SHA-1 thumbprint' }
      $store = Open-PersonalStore
      $matches = $store.Certificates.Find(0, $thumbprint)
      if ($matches.Count -ne 1) { throw "Expected one certificate with thumbprint $thumbprint, found $($matches.Count)" }
      $certificate = $matches.Item(1)
      try {
        if (-not $certificate.HasPrivateKey()) { throw 'The selected certificate has no private key' }
        $algorithmOid = [string] $certificate.PublicKey().Algorithm.Value
        $expectedOid = if ($request.algorithm -eq 'gost3410-2012-256') { '1.2.643.7.1.1.1.1' } elseif ($request.algorithm -eq 'gost3410-2012-512') { '1.2.643.7.1.1.1.2' } else { throw 'Unsupported signature algorithm' }
        if ($algorithmOid -ne $expectedOid) { throw "Certificate algorithm $algorithmOid does not match requested $($request.algorithm)" }
        $signer = New-Object -ComObject CAdESCOM.CPSigner
        $signer.Certificate = $certificate
        $signer.Options = 2
        $signer.CheckCertificate = [bool] $request.checkCertificate
        $signedData = New-Object -ComObject CAdESCOM.CadesSignedData
        $signedData.ContentEncoding = 1
        $signedData.Content = ([string] $request.data)
        $signature = ([string] $signedData.SignCades($signer, 1, [bool] $request.detached, 0)) -replace '\s', ''
        @{ ok = $true; result = @{ signature = $signature } } | ConvertTo-Json -Compress -Depth 4
      } finally { Release-Com $signedData; Release-Com $signer; Release-Com $certificate }
    } finally {
      if ($null -ne $store) { try { $store.Close() } catch {}; Release-Com $store }
    }
  } else { throw "Unsupported CryptoPro operation: $($request.operation)" }
} catch {
  $exception = $_.Exception
  @{ ok = $false; error = @{ message = [string] $exception.Message; hresult = ('0x{0:X8}' -f ($exception.HResult -band 0xffffffffL)) } } | ConvertTo-Json -Compress -Depth 4
  exit 1
}
`;

function defaultPowerShellPath(): string {
  const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
  return `${systemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
}

function runPowerShellOnce(command: CryptoProCommand, options: CryptoProCertificateProviderOptions, powershellPath: string): Promise<unknown> {
  if (process.platform !== "win32") return Promise.reject(new Error("CryptoPro CAdESCOM provider is available only on Windows"));
  const timeout = options.timeoutMilliseconds ?? 120_000, maximum = options.maxOutputBytes ?? 64 * 1024 * 1024;
  if (!Number.isSafeInteger(timeout) || timeout <= 0 || !Number.isSafeInteger(maximum) || maximum <= 0) return Promise.reject(new RangeError("invalid CryptoPro runner limits"));
  const encoded = Buffer.from(cryptoProPowerShell, "utf16le").toString("base64");
  return new Promise((resolve, reject) => {
    const child = spawn(powershellPath, ["-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-EncodedCommand", encoded], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    const stdout: Buffer[] = [], stderr: Buffer[] = [];
    let outputBytes = 0, errorBytes = 0, settled = false;
    const finish = (error?: Error, result?: unknown): void => { if (settled) return; settled = true; clearTimeout(timer); error === undefined ? resolve(result) : reject(error); };
    const timer = setTimeout(() => { child.kill(); finish(new Error(`CryptoPro command timed out after ${timeout} ms`)); }, timeout);
    child.once("error", (error) => finish(error));
    child.stdout.on("data", (chunk: Buffer) => { outputBytes += chunk.length; if (outputBytes > maximum) { child.kill(); finish(new Error(`CryptoPro command exceeded ${maximum} output bytes`)); } else stdout.push(chunk); });
    child.stderr.on("data", (chunk: Buffer) => { if (errorBytes < 64 * 1024) { stderr.push(chunk); errorBytes += chunk.length; } });
    child.once("close", (code) => {
      if (settled) return;
      const text = Buffer.concat(stdout).toString("utf8").replace(/^\uFEFF/, "").trim();
      let envelope: unknown;
      try { envelope = JSON.parse(text); }
      catch { finish(new Error(`CryptoPro command failed (${code ?? "unknown"}): ${Buffer.concat(stderr).toString("utf8").trim() || "invalid response"}`)); return; }
      const value = envelope as { ok?: unknown; result?: unknown; error?: { message?: unknown; hresult?: unknown } };
      if (value.ok === true && code === 0) finish(undefined, value.result);
      else {
        const message = typeof value.error?.message === "string" ? value.error.message : "CryptoPro command failed";
        const hresult = typeof value.error?.hresult === "string" ? ` (${value.error.hresult})` : "";
        finish(new Error(`${message}${hresult}`));
      }
    });
    child.stdin.once("error", (error) => finish(error));
    child.stdin.end(JSON.stringify(command));
  });
}

async function runPowerShell(command: CryptoProCommand, options: CryptoProCertificateProviderOptions): Promise<unknown> {
  if (options.powershellPath !== undefined) return runPowerShellOnce(command,options,options.powershellPath);
  try { return await runPowerShellOnce(command,options,defaultPowerShellPath()); }
  catch (error) {
    // CryptoPro/CAPICOM may be registered only in the 32-bit COM registry.
    // Retry only the characteristic COM null-pointer failure, not policy,
    // certificate, token or user-cancellation errors.
    const fallback=`${process.env.SystemRoot??"C:\\Windows"}\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe`;
    if (!(error instanceof Error) || !error.message.includes("0x80004003") || !existsSync(fallback)) throw error;
    return runPowerShellOnce(command,options,fallback);
  }
}

function recordResult(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`invalid CryptoPro ${label} response`);
  return value as Record<string, unknown>;
}

function cryptoProBase64(value: unknown, label: string): Uint8Array {
  if (typeof value !== "string") throw new TypeError(`invalid CryptoPro ${label}`);
  const normalized = value.replace(/\s/g, "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized)) throw new TypeError(`invalid CryptoPro ${label}`);
  return Uint8Array.from(Buffer.from(normalized, "base64"));
}

/** Uses CryptoPro CAdESCOM and the current user's Windows `My` certificate store. */
export class CryptoProCertificateProvider implements CertificateProvider {
  readonly #runner: CryptoProCommandRunner;
  public constructor(options: CryptoProCertificateProviderOptions = {}) { this.#runner = options.runner ?? ((command) => runPowerShell(command, options)); }
  public async listCertificates(): Promise<readonly CertificateInfo[]> {
    const result = await this.#runner({ operation: "list" });
    if (!Array.isArray(result)) throw new TypeError("invalid CryptoPro certificate list response");
    return result.map((value) => {
      const item = recordResult(value, "certificate");
      if (typeof item.id !== "string" || !/^sha1:[0-9a-f]{40}$/i.test(item.id) || typeof item.subject !== "string" || typeof item.issuer !== "string" || typeof item.serialNumber !== "string" || typeof item.validFrom !== "string" || typeof item.validTo !== "string" || typeof item.hasPrivateKey !== "boolean") throw new TypeError("invalid CryptoPro certificate response");
      const validFrom = new Date(item.validFrom), validTo = new Date(item.validTo);
      if (Number.isNaN(validFrom.valueOf()) || Number.isNaN(validTo.valueOf())) throw new TypeError("invalid CryptoPro certificate dates");
      const der = cryptoProBase64(item.der, "certificate DER");
      if (der.length === 0) throw new TypeError("invalid CryptoPro certificate DER");
      return { id: item.id, subject: item.subject, issuer: item.issuer, serialNumber: item.serialNumber, validFrom, validTo, der, hasPrivateKey: item.hasPrivateKey };
    });
  }
  public async validateCertificate(certificateId: string): Promise<CertificateValidationResult> {
    if (typeof certificateId !== "string" || !/^sha1:[0-9a-f]{40}$/i.test(certificateId)) throw new TypeError("certificate id must be a SHA-1 thumbprint");
    const result = recordResult(await this.#runner({ operation: "validate", certificateId }), "validation");
    if (typeof result.valid !== "boolean") throw new TypeError("invalid CryptoPro validation response");
    return { valid: result.valid, checkedAt: new Date() };
  }
  public async sign(certificateId: string, data: Uint8Array, options: SignOptions): Promise<Uint8Array> {
    if (typeof certificateId !== "string" || !/^sha1:[0-9a-f]{40}$/i.test(certificateId)) throw new TypeError("certificate id must be a SHA-1 thumbprint");
    if (!(data instanceof Uint8Array)) throw new TypeError("signing data must be Uint8Array");
    if (options.algorithm !== "gost3410-2012-256" && options.algorithm !== "gost3410-2012-512") throw new TypeError("unsupported signature algorithm");
    const result = recordResult(await this.#runner({ operation: "sign", certificateId, data: Buffer.from(data).toString("base64"), algorithm: options.algorithm, detached: options.detached ?? true, checkCertificate: options.checkCertificate ?? false }), "signature");
    return cryptoProBase64(result.signature, "signature");
  }
}

export function createCryptoProCertificateProvider(options: CryptoProCertificateProviderOptions = {}): CryptoProCertificateProvider { return new CryptoProCertificateProvider(options); }

export interface CertificateBridgeServerOptions {
  /** Shared bearer token. A non-empty value is mandatory. */
  readonly bearerToken: string;
  /** Browser origins allowed to call the agent. Requests without Origin remain allowed. */
  readonly allowedOrigins?: readonly string[];
  readonly path?: string;
  readonly maxBodyBytes?: number;
}

class RpcFailure extends Error {
  public constructor(readonly code: number, message: string, readonly status = 400) { super(message); }
}

function safeTokenEqual(received: string, expected: string): boolean {
  const left = Buffer.from(received), right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function json(response: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(body), "cache-control": "no-store" });
  response.end(body);
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new RpcFailure(-32602, "invalid params");
  return value as Record<string, unknown>;
}

function strictBase64(value: unknown): Uint8Array {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new RpcFailure(-32602, "invalid base64 data");
  return Uint8Array.from(Buffer.from(value, "base64"));
}

async function requestBody(request: IncomingMessage, maximum: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > maximum) throw new RpcFailure(-32600, "request is too large", 413);
    chunks.push(bytes);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new RpcFailure(-32700, "parse error"); }
}

async function dispatch(provider: CertificateProvider, method: unknown, parameters: unknown): Promise<unknown> {
  if (method === "certificates.list") {
    object(parameters);
    return (await provider.listCertificates()).map((certificate) => ({
      ...certificate,
      validFrom: certificate.validFrom.toISOString(),
      validTo: certificate.validTo.toISOString(),
      der: Buffer.from(certificate.der).toString("base64"),
    }));
  }
  if (method === "certificates.sign") {
    const values = object(parameters), options = object(values.options);
    if (typeof values.certificateId !== "string" || (options.algorithm !== "gost3410-2012-256" && options.algorithm !== "gost3410-2012-512") || (options.detached !== undefined && typeof options.detached !== "boolean") || (options.checkCertificate !== undefined && typeof options.checkCertificate !== "boolean")) throw new RpcFailure(-32602, "invalid signing params");
    const signature = await provider.sign(values.certificateId, strictBase64(values.data), options as unknown as SignOptions);
    return { signature: Buffer.from(signature).toString("base64") };
  }
  if (method === "certificates.validate") {
    const values = object(parameters);
    if (typeof values.certificateId !== "string") throw new RpcFailure(-32602, "invalid validation params");
    if (provider.validateCertificate === undefined) throw new RpcFailure(-32601, "certificate validation is unavailable");
    const result = await provider.validateCertificate(values.certificateId);
    return { valid: result.valid, checkedAt: result.checkedAt.toISOString() };
  }
  throw new RpcFailure(-32601, "method not found");
}

/** Creates a JSON-RPC request handler suitable for node:http or node:https. */
export function createCertificateBridgeHandler(provider: CertificateProvider, options: CertificateBridgeServerOptions): RequestListener {
  if (typeof options.bearerToken !== "string" || options.bearerToken.length === 0) throw new RangeError("certificate bridge bearer token must not be empty");
  const endpoint = options.path ?? "/rpc", maximum = options.maxBodyBytes ?? 16 * 1024 * 1024, origins = new Set(options.allowedOrigins ?? []);
  if (!endpoint.startsWith("/") || !Number.isSafeInteger(maximum) || maximum <= 0) throw new RangeError("invalid certificate bridge server options");
  return async (request, response) => {
    const origin = request.headers.origin;
    if (origin !== undefined) {
      if (!origins.has(origin)) { response.writeHead(403); response.end(); return; }
      response.setHeader("access-control-allow-origin", origin);
      response.setHeader("vary", "Origin");
      response.setHeader("access-control-allow-headers", "authorization, content-type");
      response.setHeader("access-control-allow-methods", "POST, OPTIONS");
    }
    if (request.method === "OPTIONS") { response.writeHead(204); response.end(); return; }
    if (request.method !== "POST" || new URL(request.url ?? "/", "http://localhost").pathname !== endpoint) { response.writeHead(404); response.end(); return; }
    const authorization = request.headers.authorization;
    if (authorization === undefined || !authorization.startsWith("Bearer ") || !safeTokenEqual(authorization.slice(7), options.bearerToken)) { response.writeHead(401, { "www-authenticate": "Bearer" }); response.end(); return; }
    let id: unknown = null;
    try {
      const payload = object(await requestBody(request, maximum));
      id = payload.id;
      if (payload.jsonrpc !== "2.0" || (typeof id !== "string" && typeof id !== "number" && id !== null)) throw new RpcFailure(-32600, "invalid request");
      json(response, 200, { jsonrpc: "2.0", id, result: await dispatch(provider, payload.method, payload.params) });
    } catch (error) {
      const failure = error instanceof RpcFailure ? error : new RpcFailure(-32000, error instanceof Error ? error.message : "certificate provider error", 500);
      json(response, failure.status, { jsonrpc: "2.0", id, error: { code: failure.code, message: failure.message } });
    }
  };
}

/** Creates a locked-down HTTP bridge around any certificate provider. Bind it to loopback. */
export function createCertificateBridgeServer(provider: CertificateProvider, options: CertificateBridgeServerOptions): Server {
  return createServer(createCertificateBridgeHandler(provider, options));
}
