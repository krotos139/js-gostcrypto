const certificateSelect = document.querySelector("#certificate");
const dataInput = document.querySelector("#data");
const documentInput = document.querySelector("#document");
const signatureInput = document.querySelector("#signature");
const validateButton = document.querySelector("#validate");
const signButton = document.querySelector("#sign");
const verifyButton = document.querySelector("#verify");
const download = document.querySelector("#download");
const status = document.querySelector("#status");

const smoke = window.__gostcryptoBrowserSmoke = {
  phase: "initializing",
  certificateCount: 0,
  privateKeyCertificateCount: 0,
  supportedCertificateCount: 0,
  verified: false,
  certificateValid: undefined,
};

let certificates = [];
let lastSignature;
let signatureUrl;
const provider = GostCrypto.providers.createCryptoProBrowserProvider();

function algorithmFor(certificate) {
  const spki = GostCrypto.asn1.extractSubjectPublicKeyInfo(certificate.der);
  const { algorithmOid } = GostCrypto.asn1.parseSubjectPublicKeyInfo(spki);
  if (algorithmOid === GostCrypto.asn1.OID.publicKey256) return "gost3410-2012-256";
  if (algorithmOid === GostCrypto.asn1.OID.publicKey512) return "gost3410-2012-512";
  throw new Error(`Неподдерживаемый алгоритм сертификата: ${algorithmOid}`);
}

function report(message, kind) {
  status.textContent = message;
  status.dataset.kind = kind ?? "progress";
}

async function documentBytes() {
  const file = documentInput.files?.[0];
  return file ? new Uint8Array(await file.arrayBuffer()) : new TextEncoder().encode(dataInput.value);
}

async function signatureBytes() {
  const file = signatureInput.files?.[0];
  if (file) return new Uint8Array(await file.arrayBuffer());
  if (lastSignature) return lastSignature;
  throw new Error("Сначала создайте или выберите файл подписи.");
}

function setBusy(busy) {
  const disabled = busy || certificateSelect.options.length === 0;
  certificateSelect.disabled = disabled;
  validateButton.disabled = disabled;
  signButton.disabled = disabled;
  verifyButton.disabled = busy;
}

function publishSignature(signature) {
  if (signatureUrl) URL.revokeObjectURL(signatureUrl);
  signatureUrl = URL.createObjectURL(new Blob([signature], { type: "application/pkcs7-signature" }));
  const sourceName = documentInput.files?.[0]?.name ?? "document";
  download.href = signatureUrl;
  download.download = `${sourceName}.p7s`;
  download.hidden = false;
}

async function loadCertificates() {
  try {
    certificates = [...await provider.listCertificates()];
    const withPrivateKey = certificates
      .map((certificate, index) => ({ certificate, index }))
      .filter(({ certificate }) => certificate.hasPrivateKey);
    const usable = [];
    for (const entry of withPrivateKey) {
      try { usable.push({ ...entry, algorithm: algorithmFor(entry.certificate) }); }
      catch { /* The Windows My store may also contain RSA/ECDSA certificates. */ }
    }

    certificateSelect.replaceChildren(...usable.map(({ certificate, index, algorithm }) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = `${certificate.subject} — ${algorithm}`;
      return option;
    }));

    smoke.phase = "ready";
    smoke.certificateCount = certificates.length;
    smoke.privateKeyCertificateCount = withPrivateKey.length;
    smoke.supportedCertificateCount = usable.length;
    smoke.subjects = usable.map(({ certificate }) => certificate.subject);
    certificateSelect.disabled = usable.length === 0;
    validateButton.disabled = usable.length === 0;
    signButton.disabled = usable.length === 0;
    verifyButton.disabled = false;
    report(`Готово: сертификатов ${certificates.length}, с закрытым ключом ${withPrivateKey.length}, поддерживаемых ГОСТ-2012 ${usable.length}.`, "success");
  } catch (error) {
    smoke.phase = "error";
    smoke.error = error instanceof Error ? error.message : String(error);
    report(`Ошибка перечисления сертификатов: ${smoke.error}`, "error");
  }
}

validateButton.addEventListener("click", async () => {
  const certificate = certificates[Number(certificateSelect.value)];
  if (!certificate) return;
  setBusy(true);
  smoke.phase = "validating-certificate";
  report("CryptoPro проверяет срок действия, цепочку доверия и статус сертификата…");
  try {
    const result = await provider.validateCertificate(certificate.id);
    smoke.phase = "ready";
    smoke.certificateValid = result.valid;
    smoke.certificateCheckedAt = result.checkedAt.toISOString();
    report(result.valid ? "Сертификат действителен и его цепочка доверена CryptoPro." : "CryptoPro не доверяет сертификату: проверьте срок, цепочку и отзыв.", result.valid ? "success" : "error");
  } catch (error) {
    smoke.phase = "error";
    smoke.error = error instanceof Error ? error.message : String(error);
    report(`Ошибка проверки сертификата: ${smoke.error}`, "error");
  } finally { setBusy(false); }
});

signButton.addEventListener("click", async () => {
  const certificate = certificates[Number(certificateSelect.value)];
  if (!certificate) return;

  const data = await documentBytes();
  setBusy(true);
  smoke.phase = "signing";
  smoke.verified = false;
  delete smoke.error;
  report("Создание отделённой CAdES-BES-подписи…");

  try {
    const signature = await provider.sign(certificate.id, data, {
      algorithm: algorithmFor(certificate),
      detached: true,
      checkCertificate: false,
    });
    const cms = GostCrypto.cms.parseSignedData(signature);
    cms.verify(data);

    smoke.phase = "complete";
    smoke.verified = true;
    smoke.signatureLength = signature.length;
    smoke.selectedSubject = certificate.subject;
    smoke.algorithm = algorithmFor(certificate);
    lastSignature = signature;
    publishSignature(signature);
    report(`Успешно: создана и проверена отделённая подпись (${signature.length} байт).`, "success");
  } catch (error) {
    smoke.phase = "error";
    smoke.error = error instanceof Error ? error.message : String(error);
    report(`Ошибка подписи: ${smoke.error}`, "error");
  } finally {
    setBusy(false);
  }
});

verifyButton.addEventListener("click", async () => {
  setBusy(true);
  smoke.phase = "verifying";
  smoke.verified = false;
  report("Проверка отделённой CMS/CAdES-подписи в JavaScript…");
  try {
    const data = await documentBytes();
    const signature = await signatureBytes();
    GostCrypto.cms.parseSignedData(signature).verify(data);
    smoke.phase = "complete";
    smoke.verified = true;
    smoke.signatureLength = signature.length;
    report(`Подпись корректна для выбранного документа (${signature.length} байт). Проверка доверия сертификата выполняется отдельно.`, "success");
  } catch (error) {
    smoke.phase = "error";
    smoke.error = error instanceof Error ? error.message : String(error);
    report(`Ошибка проверки подписи: ${smoke.error}`, "error");
  } finally { setBusy(false); }
});

window.addEventListener("beforeunload", () => { if (signatureUrl) URL.revokeObjectURL(signatureUrl); });

await loadCertificates();
