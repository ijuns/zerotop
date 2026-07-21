import { createHash } from "node:crypto";

import type { ArtifactScanner } from "./artifact-scanner.ts";
import type { AiValidationClient, SandboxRunner } from "./clients.ts";
import { parseLabTarget, type JsonObject, type PublishDecision } from "./contracts.ts";

export interface ValidationServiceDependencies {
  artifactScanner: ArtifactScanner;
  sandboxRunner: SandboxRunner;
  ai: AiValidationClient;
  allowedRegistries: string[];
}

export class ValidationService {
  private readonly dependencies: ValidationServiceDependencies;

  constructor(dependencies: ValidationServiceDependencies) {
    this.dependencies = dependencies;
  }

  async validate(labValue: unknown): Promise<JsonObject> {
    const target = parseLabTarget(labValue, this.dependencies.allowedRegistries);
    const artifact = await this.dependencies.artifactScanner.scan(target);
    const sandbox = await this.dependencies.sandboxRunner.validate(target);
    const aiReview = await this.dependencies.ai.review(target, artifact, sandbox);
    const validation = await this.dependencies.ai.publish(target, {
      artifact,
      sandbox: sandbox.sandbox,
      assessment: sandbox.assessment,
      aiReview,
    });
    return response(target.labId, validation);
  }
}

function response(labId: string, validation: PublishDecision): JsonObject {
  const evidence = validation.checks.map((check) => ({
    id: `evidence_${createHash("sha256").update(`${labId}:${check.id}`).digest("hex").slice(0, 24)}`,
    checkName: check.id,
    outcome: check.passed ? "pass" : "fail",
    details: {
      label: check.label,
      mandatory: check.mandatory,
      ...check.details,
    },
  }));
  return {
    decision: validation.decision,
    status: validation.decision === "pass" ? "validated" : "quarantined",
    evidence,
    validation,
  };
}
