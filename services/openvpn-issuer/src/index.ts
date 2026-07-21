import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";

import { BundleCipher } from "./crypto.ts";
import { runGatewayFromEnvironment } from "./gateway.ts";
import { createIssuerHttpServer } from "./http.ts";
import { OpenSslCertificateAuthority } from "./pki.ts";
import { PostgresProfileRepository } from "./postgres.ts";
import { OpenVpnProfileService } from "./service.ts";
import { PlatformApiTicketExchanger } from "./ticket.ts";

async function main(): Promise<void> {
  const mode =
    process.env.OPENVPN_MODE ??
    (process.env.OPENVPN_RUN_ID ? "gateway" : "issuer");
  if (mode === "gateway") {
    await runGatewayFromEnvironment();
    return;
  }
  if (mode !== "issuer") throw new Error("OPENVPN_MODE must be issuer or gateway.");

  const port = integer(
    process.env.ISSUER_PORT ?? process.env.PORT ?? "9100",
    "ISSUER_PORT",
    1,
    65535,
  );
  const maxTtlMinutes = integer(
    process.env.OPENVPN_PROFILE_TTL_MAX_MINUTES ?? "240",
    "OPENVPN_PROFILE_TTL_MAX_MINUTES",
    10,
    1440,
  );
  const databaseUrl = required("DATABASE_URL");
  const platformApiUrl = required("PLATFORM_API_URL");
  const issuerToken = secret("OPENVPN_ISSUER_TOKEN", 24);
  const downloadToken = secret("OPENVPN_DOWNLOAD_INTERNAL_TOKEN", 24);
  const masterKey = required("OPENVPN_MASTER_KEY");
  const allowedCidr = required("OPENVPN_ALLOWED_CIDR");
  const caCertificatePath =
    process.env.OPENVPN_CA_CERT_PATH ?? "/etc/openvpn/pki/ca.crt";
  const caPrivateKeyPath =
    process.env.OPENVPN_CA_KEY_PATH ?? "/etc/openvpn/pki/ca.key";
  const tlsCryptKeyPath =
    process.env.OPENVPN_TLS_CRYPT_PATH ?? "/etc/openvpn/pki/tls-crypt.key";
  const opensslPath = process.env.OPENSSL_BINARY ?? "openssl";
  const [caCertificate, caPrivateKey, tlsCryptKey] = await Promise.all([
    readFile(caCertificatePath, "utf8"),
    readFile(caPrivateKeyPath, "utf8"),
    readFile(tlsCryptKeyPath, "utf8"),
  ]);
  if (
    !caCertificate.includes("-----BEGIN CERTIFICATE-----") ||
    !/-----BEGIN (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----/.test(caPrivateKey) ||
    !tlsCryptKey.includes("-----BEGIN OpenVPN Static key V1-----")
  ) {
    throw new Error("Mounted OpenVPN PKI material is invalid.");
  }
  await executeVersion(opensslPath);
  const cipher = BundleCipher.fromBase64(masterKey);
  const ticketExchanger = new PlatformApiTicketExchanger({
    apiUrl: platformApiUrl,
    internalToken: downloadToken,
  });
  const repository = new PostgresProfileRepository(databaseUrl);
  await repository.initialize();
  const operations = new OpenVpnProfileService({
    repository,
    certificateAuthority: new OpenSslCertificateAuthority({
      caCertificatePath,
      caPrivateKeyPath,
      tlsCryptKeyPath,
      workingDirectory: process.env.OPENVPN_WORK_DIR ?? "/run/openvpn",
      opensslPath,
      ...(process.env.OPENVPN_CA_KEY_PASSPHRASE_FILE
        ? {
            caPrivateKeyPassphraseFile:
              process.env.OPENVPN_CA_KEY_PASSPHRASE_FILE,
          }
        : {}),
    }),
    cipher,
    ticketExchanger,
    vpnCidr: process.env.OPENVPN_CLIENT_CIDR ?? "10.203.0.0/24",
  });
  const server = createIssuerHttpServer({
    operations,
    issuerToken,
    maxTtlMinutes,
    allowedCidr,
  });
  server.listen(port, "0.0.0.0", () => {
    console.log(JSON.stringify({ level: "info", service: "openvpn-issuer", port }));
  });

  let closing = false;
  const shutdown = (): void => {
    if (closing) return;
    closing = true;
    server.close(() => {
      void repository.close().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function secret(name: string, minimum: number): string {
  const value = required(name);
  if (value.length < minimum) {
    throw new Error(`${name} must contain at least ${minimum} characters.`);
  }
  return value;
}

function integer(
  raw: string,
  name: string,
  minimum: number,
  maximum: number,
): number {
  const value = Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} is invalid.`);
  }
  return value;
}

function executeVersion(opensslPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(
      opensslPath,
      ["version"],
      { windowsHide: true, timeout: 5_000, maxBuffer: 64 * 1024 },
      (error) => (error ? reject(error) : resolve()),
    );
  });
}

void main().catch((error: unknown) => {
  console.error(
    JSON.stringify({
      level: "error",
      service: "openvpn-issuer",
      message: error instanceof Error ? error.message : "Startup failure",
    }),
  );
  process.exitCode = 1;
});
