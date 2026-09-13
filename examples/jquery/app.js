import $ from "jquery";
import { extractSubjectPublicKeyInfo, OID, parseSubjectPublicKeyInfo } from "@gostcrypto/asn1";
import { parseSignedData } from "@gostcrypto/cms";
import { installGostCrypto } from "@gostcrypto/jquery";
import { createCryptoProBrowserProvider } from "@gostcrypto/providers";

function algorithmFor(certificate) {
  const { algorithmOid } = parseSubjectPublicKeyInfo(extractSubjectPublicKeyInfo(certificate.der));
  if (algorithmOid === OID.publicKey256) return "gost3410-2012-256";
  if (algorithmOid === OID.publicKey512) return "gost3410-2012-512";
  throw new Error(`Unsupported certificate algorithm: ${algorithmOid}`);
}

installGostCrypto($, createCryptoProBrowserProvider());

const usable = [];
try {
  for (const certificate of await $.gostCrypto.listCertificates()) {
    if (!certificate.hasPrivateKey) continue;
    try { usable.push({ certificate, algorithm: algorithmFor(certificate) }); }
    catch { /* Ignore RSA and other certificates from the Windows My store. */ }
  }
  $("#certificate").append(usable.map(({ certificate, algorithm }, index) =>
    $("<option>").val(index).text(`${certificate.subject} — ${algorithm}`),
  ));
  $("#sign").prop("disabled", usable.length === 0);
  $("#status").text(`${usable.length} supported certificate(s)`);
} catch (error) {
  $("#status").text(error instanceof Error ? error.message : String(error));
}

$("#sign").on("click", async () => {
  const selected = usable[Number($("#certificate").val())];
  if (selected === undefined) return;
  $("#sign").prop("disabled", true);
  $("#status").text("Signing with CryptoPro…");
  try {
    const document = new TextEncoder().encode(String($("#data").val()));
    const signature = await $.gostCrypto.sign(selected.certificate.id, document, {
      algorithm: selected.algorithm,
      detached: true,
      checkCertificate: false,
    });
    parseSignedData(signature).verify(document);
    $("#status").text(`Signature created and verified (${signature.length} bytes).`);
  } catch (error) {
    $("#status").text(error instanceof Error ? error.message : String(error));
  } finally {
    $("#sign").prop("disabled", false);
  }
});
