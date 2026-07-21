import { createHash, randomBytes } from "node:crypto";

/** Join codes are 192-bit random capabilities; only this digest is persisted. */
export function generateOrganizationJoinCode(): string {
  return `cg_${randomBytes(24).toString("base64url")}`;
}

export function hashOrganizationJoinCode(value: string): string {
  return createHash("sha256")
    .update(value.trim().toLowerCase(), "utf8")
    .digest("hex");
}
