import { useMemo, useState } from "react";
import { extractSubjectPublicKeyInfo, OID, parseSubjectPublicKeyInfo } from "@gostcrypto/asn1";
import { parseSignedData } from "@gostcrypto/cms";
import { useCertificates, useGostSign } from "@gostcrypto/react";

function algorithmFor(certificate) {
  const spki = extractSubjectPublicKeyInfo(certificate.der);
  const { algorithmOid } = parseSubjectPublicKeyInfo(spki);
  if (algorithmOid === OID.publicKey256) return "gost3410-2012-256";
  if (algorithmOid === OID.publicKey512) return "gost3410-2012-512";
  throw new Error(`Unsupported certificate algorithm: ${algorithmOid}`);
}

async function inputBytes(file, text) {
  return file ? new Uint8Array(await file.arrayBuffer()) : new TextEncoder().encode(text);
}

export function App() {
  const { certificates, loading, error, refresh } = useCertificates();
  const sign = useGostSign();
  const usable = useMemo(() => certificates.flatMap((certificate) => {
    if (!certificate.hasPrivateKey) return [];
    try { return [{ certificate, algorithm: algorithmFor(certificate) }]; }
    catch { return []; }
  }), [certificates]);
  const [selectedId, setSelectedId] = useState("");
  const [text, setText] = useState("gostcrypto-js React example");
  const [file, setFile] = useState();
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  const selected = usable.find(({ certificate }) => certificate.id === selectedId) ?? usable[0];

  async function handleSign() {
    if (selected === undefined) return;
    setBusy(true);
    setStatus("Signing with CryptoPro…");
    try {
      const data = await inputBytes(file, text);
      const signature = await sign(selected.certificate.id, data, {
        algorithm: selected.algorithm,
        detached: true,
        checkCertificate: false,
      });
      parseSignedData(signature).verify(data);

      const url = URL.createObjectURL(new Blob([signature], { type: "application/pkcs7-signature" }));
      const link = Object.assign(document.createElement("a"), {
        href: url,
        download: `${file?.name ?? "document"}.p7s`,
      });
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
      setStatus(`Signature created and verified (${signature.length} bytes).`);
    } catch (reason) {
      setStatus(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <h1>gostcrypto-js + React</h1>
      <p>The private key remains in CryptoPro CSP or on the USB token.</p>

      {loading && <p>Reading certificates…</p>}
      {error && <button onClick={refresh}>Retry: {String(error)}</button>}

      <label>
        GOST certificate with a private key
        <select value={selected?.certificate.id ?? ""} onChange={(event) => setSelectedId(event.target.value)}>
          {usable.map(({ certificate, algorithm }) => (
            <option key={certificate.id} value={certificate.id}>{certificate.subject} — {algorithm}</option>
          ))}
        </select>
      </label>

      <label>
        Text to sign
        <textarea value={text} onChange={(event) => setText(event.target.value)} />
      </label>

      <label>
        Or choose a file
        <input type="file" onChange={(event) => setFile(event.target.files?.[0])} />
      </label>

      <button disabled={busy || selected === undefined} onClick={handleSign}>
        {busy ? "Signing…" : "Sign, verify, and download .p7s"}
      </button>
      <output>{status || `${usable.length} supported certificate(s)`}</output>
    </main>
  );
}
