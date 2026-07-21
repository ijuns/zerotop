import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";

import type { CertificateAuthority, CertificateMaterial } from "./types.ts";

export type CommandRunner = (executable: string, args: string[]) => Promise<void>;

interface OpenSslCertificateAuthorityOptions {
  caCertificatePath: string;
  caPrivateKeyPath: string;
  tlsCryptKeyPath: string;
  workingDirectory: string;
  opensslPath?: string;
  caPrivateKeyPassphraseFile?: string;
  commandRunner?: CommandRunner;
}

export class OpenSslCertificateAuthority implements CertificateAuthority {
  private readonly options: OpenSslCertificateAuthorityOptions;
  private readonly run: CommandRunner;

  constructor(options: OpenSslCertificateAuthorityOptions) {
    this.options = options;
    this.run = options.commandRunner ?? execute;
  }

  async issue(profileId: string, expiresAt: string): Promise<CertificateMaterial> {
    await mkdir(this.options.workingDirectory, { recursive: true, mode: 0o700 });
    const temporary = await mkdtemp(join(this.options.workingDirectory, "sign-"));
    const clientCommonName = commonName("client", profileId);
    const serverCommonName = commonName("server", profileId);
    try {
      const [caCertificate, tlsCryptKey] = await Promise.all([
        readFile(this.options.caCertificatePath, "utf8"),
        readFile(this.options.tlsCryptKeyPath, "utf8"),
      ]);
      const client = await this.issueLeaf(
        temporary,
        "client",
        clientCommonName,
        "clientAuth",
        expiresAt,
      );
      const server = await this.issueLeaf(
        temporary,
        "server",
        serverCommonName,
        "serverAuth",
        expiresAt,
      );
      return {
        caCertificate,
        tlsCryptKey,
        clientCertificate: client.certificate,
        clientPrivateKey: client.privateKey,
        clientCommonName,
        serverCertificate: server.certificate,
        serverPrivateKey: server.privateKey,
        serverCommonName,
      };
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  }

  private async issueLeaf(
    directory: string,
    label: string,
    commonNameValue: string,
    usage: "clientAuth" | "serverAuth",
    expiresAt: string,
  ): Promise<{ certificate: string; privateKey: string }> {
    const privateKey = join(directory, `${label}.key`);
    const request = join(directory, `${label}.csr`);
    const certificate = join(directory, `${label}.crt`);
    const extensions = join(directory, `${label}.ext`);
    await writeFile(
      extensions,
      `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=${usage}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n`,
      { mode: 0o600 },
    );
    const openssl = this.options.opensslPath ?? "openssl";
    await this.run(openssl, [
      "genpkey",
      "-algorithm",
      "EC",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-out",
      privateKey,
    ]);
    await chmod(privateKey, 0o600);
    await this.run(openssl, [
      "req",
      "-new",
      "-sha256",
      "-key",
      privateKey,
      "-out",
      request,
      "-subj",
      `/CN=${commonNameValue}`,
    ]);
    const remainingMs = Date.parse(expiresAt) - Date.now();
    const days = Math.max(1, Math.ceil(remainingMs / 86_400_000));
    await this.run(openssl, [
      "x509",
      "-req",
      "-sha256",
      "-in",
      request,
      "-CA",
      this.options.caCertificatePath,
      "-CAkey",
      this.options.caPrivateKeyPath,
      ...(this.options.caPrivateKeyPassphraseFile
        ? ["-passin", `file:${this.options.caPrivateKeyPassphraseFile}`]
        : []),
      "-set_serial",
      `0x${randomBytes(16).toString("hex")}`,
      "-days",
      String(days),
      "-extfile",
      extensions,
      "-out",
      certificate,
    ]);
    return {
      certificate: await readFile(certificate, "utf8"),
      privateKey: await readFile(privateKey, "utf8"),
    };
  }
}

function commonName(kind: "client" | "server", profileId: string): string {
  const suffix = profileId.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 48);
  return `codegate-${kind}-${suffix}`;
}

function execute(executable: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(
      executable,
      args,
      { windowsHide: true, timeout: 15_000, maxBuffer: 1024 * 1024 },
      (error) => (error ? reject(error) : resolve()),
    );
  });
}
