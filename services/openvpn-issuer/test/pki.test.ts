import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { OpenSslCertificateAuthority } from "../src/pki.ts";

test("certificate authority invokes openssl without a command shell", async () => {
  const directory = await mkdtemp(join(tmpdir(), "codegate-pki-test-"));
  const ca = join(directory, "ca.crt");
  const caKey = join(directory, "ca.key");
  const tlsCrypt = join(directory, "tls-crypt.key");
  await writeFile(ca, "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n");
  await writeFile(caKey, "-----BEGIN PRIVATE KEY-----\nca\n-----END PRIVATE KEY-----\n");
  await writeFile(tlsCrypt, "-----BEGIN OpenVPN Static key V1-----\ntls\n-----END OpenVPN Static key V1-----\n");
  const commands: Array<{ executable: string; args: string[] }> = [];
  try {
    const authority = new OpenSslCertificateAuthority({
      caCertificatePath: ca,
      caPrivateKeyPath: caKey,
      tlsCryptKeyPath: tlsCrypt,
      workingDirectory: directory,
      opensslPath: "/usr/bin/openssl",
      commandRunner: async (executable, args) => {
        commands.push({ executable, args });
        const outputIndex = args.indexOf("-out");
        assert.ok(outputIndex >= 0);
        const output = args[outputIndex + 1];
        if (args[0] === "genpkey") {
          await writeFile(output, "-----BEGIN PRIVATE KEY-----\nleaf\n-----END PRIVATE KEY-----\n");
        } else if (args[0] === "req") {
          await writeFile(output, "certificate request");
        } else if (args[0] === "x509") {
          await writeFile(output, "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n");
        }
      },
    });
    const material = await authority.issue(
      "vpn-profile-1",
      new Date(Date.now() + 60 * 60_000).toISOString(),
    );
    assert.match(material.clientCertificate, /BEGIN CERTIFICATE/);
    assert.match(material.serverPrivateKey, /BEGIN PRIVATE KEY/);
    assert.equal(commands.length, 6);
    assert.ok(commands.every((item) => item.executable === "/usr/bin/openssl"));
    assert.ok(commands.every((item) => Array.isArray(item.args)));
    assert.match(await readFile(ca, "utf8"), /BEGIN CERTIFICATE/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
