import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

export interface EncryptedPayload {
  version: 1;
  algorithm: "AES-256-GCM";
  iv: string;
  authenticationTag: string;
  ciphertext: string;
}

export class BundleCipher {
  private readonly key: Buffer;

  constructor(key: Buffer) {
    if (key.length !== 32) throw new Error("The bundle master key must be 32 bytes.");
    this.key = Buffer.from(key);
  }

  static fromBase64(value: string): BundleCipher {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
      throw new Error("OPENVPN_MASTER_KEY must be canonical base64.");
    }
    const key = Buffer.from(value, "base64");
    if (key.length !== 32 || key.toString("base64") !== value) {
      throw new Error("OPENVPN_MASTER_KEY must decode to exactly 32 bytes.");
    }
    return new BundleCipher(key);
  }

  encrypt(value: unknown, associatedData: string): EncryptedPayload {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(associatedData, "utf8"));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(value), "utf8"),
      cipher.final(),
    ]);
    return {
      version: 1,
      algorithm: "AES-256-GCM",
      iv: iv.toString("base64"),
      authenticationTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
  }

  decrypt<T>(payload: EncryptedPayload, associatedData: string): T {
    if (
      payload.version !== 1 ||
      payload.algorithm !== "AES-256-GCM" ||
      !payload.iv ||
      !payload.authenticationTag ||
      !payload.ciphertext
    ) {
      throw new Error("The encrypted bundle envelope is invalid.");
    }
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(payload.iv, "base64"),
    );
    decipher.setAAD(Buffer.from(associatedData, "utf8"));
    decipher.setAuthTag(Buffer.from(payload.authenticationTag, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(payload.ciphertext, "base64")),
      decipher.final(),
    ]).toString("utf8");
    return JSON.parse(plaintext) as T;
  }
}

export function bundleAssociatedData(
  kind: "client" | "server",
  runId: string,
  profileId: string,
): string {
  return `codegate-openvpn:v1:${kind}:${runId}:${profileId}`;
}
