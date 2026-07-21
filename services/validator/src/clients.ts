import type {
  AiReviewEvidence,
  ArtifactEvidence,
  LabTarget,
  PublishDecision,
  SandboxResult,
} from "./contracts.ts";
import { parseAiReview, parsePublishDecision, parseSandboxResult } from "./contracts.ts";

export interface SandboxRunner {
  validate(target: LabTarget): Promise<SandboxResult>;
}

export interface AiValidationClient {
  review(target: LabTarget, artifact: ArtifactEvidence, sandbox: SandboxResult): Promise<AiReviewEvidence>;
  publish(target: LabTarget, evidence: {
    artifact: ArtifactEvidence;
    sandbox: SandboxResult["sandbox"];
    assessment: SandboxResult["assessment"];
    aiReview: AiReviewEvidence;
  }): Promise<PublishDecision>;
}

export class HttpSandboxRunner implements SandboxRunner {
  private readonly url: string;
  private readonly token: string;

  constructor(url: string, token: string) {
    this.url = url.replace(/\/$/, "");
    this.token = strongToken(token, "SANDBOX_RUNNER_INTERNAL_TOKEN");
  }

  async validate(target: LabTarget): Promise<SandboxResult> {
    const payload = await postJson(
      `${this.url}/v1/validation-runs`,
      this.token,
      { lab: target.lab, image: `${target.image}@${target.digest}` },
      300_000,
    );
    return parseSandboxResult(payload, target.team);
  }
}

export class HttpAiValidationClient implements AiValidationClient {
  private readonly url: string;
  private readonly token: string;

  constructor(url: string, token: string) {
    this.url = url.replace(/\/$/, "");
    this.token = strongToken(token, "AI_INTERNAL_TOKEN");
  }

  async review(target: LabTarget, artifact: ArtifactEvidence, sandbox: SandboxResult): Promise<AiReviewEvidence> {
    return parseAiReview(await postJson(
      `${this.url}/v1/review/validation`,
      this.token,
      { lab: target.lab, evidence: { artifact, ...sandbox } },
      45_000,
    ));
  }

  async publish(target: LabTarget, evidence: {
    artifact: ArtifactEvidence;
    sandbox: SandboxResult["sandbox"];
    assessment: SandboxResult["assessment"];
    aiReview: AiReviewEvidence;
  }): Promise<PublishDecision> {
    return parsePublishDecision(await postJson(
      `${this.url}/v1/publish-validation`,
      this.token,
      { lab: target.lab, evidence },
      45_000,
    ));
  }
}

async function postJson(url: string, token: string, body: unknown, timeout: number): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeout),
    });
  } catch (error) {
    throw new Error(`Internal validation dependency is unavailable: ${error instanceof Error ? error.message : "network error"}`);
  }
  if (!response.ok) throw new Error(`Internal validation dependency returned HTTP ${response.status}`);
  return await response.json();
}

function strongToken(value: string, name: string): string {
  if (value.length < 24) throw new Error(`${name} must contain at least 24 characters`);
  return value;
}
