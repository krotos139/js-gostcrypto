/** A binary value accepted by every gostcrypto package. */
export type Bytes = Uint8Array;

/** A fixed-size block cipher that never mutates its input block. */
export interface BlockCipher {
  readonly blockSize: number;
  encryptBlock(block: Bytes): Bytes;
  decryptBlock(block: Bytes): Bytes;
}

export interface CertificateInfo {
  readonly id: string;
  readonly subject: string;
  readonly issuer: string;
  readonly serialNumber: string;
  readonly validFrom: Date;
  readonly validTo: Date;
  readonly der: Bytes;
  readonly hasPrivateKey: boolean;
}

export interface SignOptions {
  readonly algorithm: "gost3410-2012-256" | "gost3410-2012-512";
  readonly detached?: boolean;
  /** Ask the native provider to validate the certificate chain before signing. */
  readonly checkCertificate?: boolean;
}

export interface CertificateValidationResult {
  /** Whether the provider trusts the certificate at the time of the check. */
  readonly valid: boolean;
  readonly checkedAt: Date;
}

/**
 * Abstraction over a source of certificates and private-key operations.
 * Implementations may represent a PFX file, a hardware token, or a native
 * bridge to the operating system certificate store.
 */
export interface CertificateProvider {
  listCertificates(): Promise<readonly CertificateInfo[]>;
  sign(certificateId: string, data: Bytes, options: SignOptions): Promise<Bytes>;
  /** Optional because file-backed providers do not necessarily have a trust store. */
  validateCertificate?(certificateId: string): Promise<CertificateValidationResult>;
}
