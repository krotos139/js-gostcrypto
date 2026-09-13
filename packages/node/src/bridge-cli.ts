#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createServer as createHttpsServer } from "node:https";
import { createCertificateBridgeHandler, createCertificateBridgeServer, createCryptoProCertificateProvider } from "./index.js";

interface CliOptions {
  readonly host: string;
  readonly port: number;
  readonly origins: readonly string[];
  readonly tokenEnvironment: string;
  readonly tlsCertificate?: string;
  readonly tlsKey?: string;
  readonly powershellPath?: string;
  readonly allowHttp: boolean;
  readonly help: boolean;
}

const usage = `Usage: gostcrypto-bridge [options]

Options:
  --origin <url>       Allowed browser origin; may be repeated
  --host <address>     Listen address (default: 127.0.0.1)
  --port <number>      Listen port (default: 19443)
  --tls-cert <path>    PEM TLS certificate
  --tls-key <path>     PEM TLS private key
  --allow-http         Explicitly allow unencrypted local development
  --token-env <name>   Bearer-token environment variable
                       (default: GOSTCRYPTO_BRIDGE_TOKEN)
  --powershell <path>  Windows PowerShell executable for CAdESCOM
  --help               Show this help
`;

function parseArguments(arguments_: readonly string[]): CliOptions {
  let host = "127.0.0.1", port = 19443, tokenEnvironment = "GOSTCRYPTO_BRIDGE_TOKEN";
  let tlsCertificate: string | undefined, tlsKey: string | undefined, powershellPath: string | undefined;
  let allowHttp = false, help = false;
  const origins: string[] = [];
  const value = (index: number, name: string): string => {
    const result = arguments_[index + 1];
    if (result === undefined || result.startsWith("--")) throw new Error(`${name} requires a value`);
    return result;
  };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index]!;
    if (argument === "--help") help = true;
    else if (argument === "--allow-http") allowHttp = true;
    else if (argument === "--origin") { origins.push(value(index, argument)); index += 1; }
    else if (argument === "--host") { host = value(index, argument); index += 1; }
    else if (argument === "--port") { port = Number(value(index, argument)); index += 1; }
    else if (argument === "--token-env") { tokenEnvironment = value(index, argument); index += 1; }
    else if (argument === "--tls-cert") { tlsCertificate = value(index, argument); index += 1; }
    else if (argument === "--tls-key") { tlsKey = value(index, argument); index += 1; }
    else if (argument === "--powershell") { powershellPath = value(index, argument); index += 1; }
    else throw new Error(`unknown option: ${argument}`);
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error("port must be an integer from 1 to 65535");
  if (host.length === 0 || tokenEnvironment.length === 0) throw new Error("host and token environment name must not be empty");
  if ((tlsCertificate === undefined) !== (tlsKey === undefined)) throw new Error("--tls-cert and --tls-key must be used together");
  if (tlsCertificate === undefined && !allowHttp && !help) throw new Error("TLS is required; provide --tls-cert and --tls-key, or explicitly use --allow-http for local development");
  for (const origin of origins) {
    const url = new URL(origin);
    if (url.origin !== origin || (url.protocol !== "https:" && !(allowHttp && url.protocol === "http:"))) throw new Error(`invalid allowed origin: ${origin}`);
  }
  return { host, port, origins, tokenEnvironment, ...(tlsCertificate === undefined ? {} : { tlsCertificate, tlsKey }), ...(powershellPath === undefined ? {} : { powershellPath }), allowHttp, help };
}

async function main(): Promise<void> {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) { process.stdout.write(usage); return; }
  const bearerToken = process.env[options.tokenEnvironment];
  if (bearerToken === undefined || bearerToken.length < 32) throw new Error(`${options.tokenEnvironment} must contain a bearer token of at least 32 characters`);
  const provider = createCryptoProCertificateProvider(options.powershellPath === undefined ? {} : { powershellPath: options.powershellPath });
  const handlerOptions = { bearerToken, allowedOrigins: options.origins };
  const server = options.tlsCertificate === undefined
    ? createCertificateBridgeServer(provider, handlerOptions)
    : createHttpsServer({ cert: await readFile(options.tlsCertificate), key: await readFile(options.tlsKey!) }, createCertificateBridgeHandler(provider, handlerOptions));
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(options.port, options.host, resolve); });
  const protocol = options.tlsCertificate === undefined ? "http" : "https";
  process.stdout.write(`gostcrypto bridge listening on ${protocol}://${options.host}:${options.port}/rpc\n`);
  const close = (): void => { server.close((error) => { if (error !== undefined) process.stderr.write(`${error.message}\n`); process.exitCode = error === undefined ? 0 : 1; }); };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}

main().catch((error: unknown) => {
  process.stderr.write(`gostcrypto-bridge: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
