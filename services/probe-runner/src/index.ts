import { Buffer } from "node:buffer";
import { executeProbePlan } from "./probe.ts";
import { parseProbePlan } from "./validation.ts";

try {
  const encoded = process.env.VALIDATION_PLAN_B64;
  if (!encoded || encoded.length > 128_000) throw new Error("VALIDATION_PLAN_B64 is required");
  const decoded = Buffer.from(encoded, "base64url").toString("utf8");
  const plan = parseProbePlan(JSON.parse(decoded) as unknown);
  const result = await executeProbePlan(plan);
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`Probe runner failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
  process.exitCode = 2;
}
