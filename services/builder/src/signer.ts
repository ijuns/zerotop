import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const CANONICAL_IMAGE = /^[a-z0-9.-]+(?::\d+)?\/[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[a-z0-9._-]+)?@sha256:[a-f0-9]{64}$/;

export interface ImageSigner {
  verifyMaterial(canonicalImage: string): Promise<void>;
  signAndVerify(canonicalImage: string): Promise<void>;
}

export class CosignImageSigner implements ImageSigner {
  private readonly cosignBin: string;
  private readonly keyRef: string;
  private readonly publicKeyPath: string;
  private readonly passwordFile: string;
  private readonly dockerConfigDirectory?: string;
  private readonly verifiedMaterials = new Map<string, number>();

  constructor(options: {
    cosignBin?: string;
    keyRef: string;
    publicKeyPath: string;
    passwordFile: string;
    dockerConfigDirectory?: string;
  }) {
    this.cosignBin = options.cosignBin ?? "cosign";
    this.keyRef = options.keyRef;
    this.publicKeyPath = options.publicKeyPath;
    this.passwordFile = options.passwordFile;
    this.dockerConfigDirectory = options.dockerConfigDirectory;
    if (!this.keyRef || !this.publicKeyPath || !this.passwordFile) throw new Error("Cosign signing material is required");
  }

  async verifyMaterial(canonicalImage: string): Promise<void> {
    if (!CANONICAL_IMAGE.test(canonicalImage)) throw new Error("Material verification requires a canonical digest-pinned image");
    const now = Date.now();
    if ((this.verifiedMaterials.get(canonicalImage) ?? 0) > now) return;
    await this.run(["verify", "--key", this.publicKeyPath, canonicalImage], this.registryEnvironment());
    this.verifiedMaterials.set(canonicalImage, now + 5 * 60_000);
  }

  async signAndVerify(canonicalImage: string): Promise<void> {
    if (!CANONICAL_IMAGE.test(canonicalImage)) throw new Error("Signing requires a canonical digest-pinned image");
    const passwordBytes = await readFile(this.passwordFile);
    if (passwordBytes.byteLength < 16 || passwordBytes.byteLength > 4_096) throw new Error("Cosign password file is invalid");
    const password = passwordBytes.toString("utf8").trimEnd();
    if (password.length < 16) throw new Error("Cosign password is too short");
    const environment = {
      ...this.registryEnvironment(),
      COSIGN_PASSWORD: password,
    };
    await this.run(["sign", "--yes", "--key", this.keyRef, canonicalImage], environment);
    await this.run(["verify", "--key", this.publicKeyPath, canonicalImage], environment);
  }

  private registryEnvironment(): NodeJS.ProcessEnv {
    return registryToolEnvironment(process.env, this.dockerConfigDirectory);
  }

  private async run(args: string[], env: NodeJS.ProcessEnv): Promise<void> {
    await execFileAsync(this.cosignBin, args, {
      timeout: 120_000,
      maxBuffer: 2_000_000,
      windowsHide: true,
      env,
    });
  }
}

export function registryToolEnvironment(
  source: NodeJS.ProcessEnv,
  dockerConfigDirectory?: string,
): NodeJS.ProcessEnv {
  return {
    PATH: source.PATH,
    HOME: "/tmp/codegate-builder-home",
    ...optionalEnvironment(source, "DOCKER_CONFIG"),
    ...optionalEnvironment(source, "SSL_CERT_DIR"),
    ...optionalEnvironment(source, "SSL_CERT_FILE"),
    ...optionalEnvironment(source, "COSIGN_REPOSITORY"),
    ...(dockerConfigDirectory ? { DOCKER_CONFIG: dockerConfigDirectory } : {}),
  };
}

function optionalEnvironment(source: NodeJS.ProcessEnv, name: string): NodeJS.ProcessEnv {
  const value = source[name];
  return typeof value === "string" && value.length > 0 ? { [name]: value } : {};
}
