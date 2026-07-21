import assert from "node:assert/strict";
import { test } from "node:test";

import { BuildCatalog } from "../src/catalog.ts";
import type { BuildRecord } from "../src/contracts.ts";
import type { BuildRunner, KubernetesBuildInspection } from "../src/kubernetes.ts";
import type { BuildRepository, BuildTransition, CreateRecordResult } from "../src/repository.ts";
import { BuildService } from "../src/service.ts";
import { parseSandboxValidationRequest } from "../../runtime/src/validation-input.ts";
import { ARTIFACT_URL, BASE_IMAGE, HEX_B, HEX_C, OUTPUT_REPOSITORY, PACKAGE_IMAGE, PACKAGE_RUNTIME_KIND, validBlueInput } from "./fixtures.ts";

class MemoryRepository implements BuildRepository {
  readonly rows = new Map<string, BuildRecord>();

  async migrate(): Promise<void> {}

  async create(record: BuildRecord): Promise<CreateRecordResult> {
    const existing = [...this.rows.values()].find((item) => item.requestedBy === record.requestedBy && item.idempotencyKey === record.idempotencyKey);
    if (existing) {
      if (existing.requestDigest !== record.requestDigest) throw new Error("idempotency conflict");
      return { record: structuredClone(existing), created: false };
    }
    this.rows.set(record.id, structuredClone(record));
    return { record: structuredClone(record), created: true };
  }

  async get(id: string): Promise<BuildRecord | null> {
    const row = this.rows.get(id);
    return row ? structuredClone(row) : null;
  }

  async listActive(limit: number): Promise<BuildRecord[]> {
    return [...this.rows.values()].filter((item) => item.status === "queued" || item.status === "running").slice(0, limit).map((item) => structuredClone(item));
  }

  async listCleanupPending(limit: number): Promise<BuildRecord[]> {
    return [...this.rows.values()].filter((item) => item.status !== "queued" && item.status !== "running" && !item.cleanedAt).slice(0, limit).map((item) => structuredClone(item));
  }

  async transition(id: string, transition: BuildTransition): Promise<BuildRecord | null> {
    const row = this.rows.get(id);
    if (!row || !transition.from.includes(row.status)) return null;
    const updated: BuildRecord = {
      ...row,
      status: transition.to,
      ...(transition.startedAt ? { startedAt: transition.startedAt } : {}),
      ...(transition.finishedAt ? { finishedAt: transition.finishedAt } : {}),
      ...(transition.imageRef ? { imageRef: transition.imageRef } : {}),
      ...(transition.imageDigest ? { imageDigest: transition.imageDigest } : {}),
      ...(transition.buildProvenance ? { buildProvenance: transition.buildProvenance } : {}),
      ...(transition.consumable ? { consumable: transition.consumable } : {}),
      ...(transition.failureCode ? { failureCode: transition.failureCode } : {}),
      ...(transition.failureDetail ? { failureDetail: transition.failureDetail } : {}),
    };
    this.rows.set(id, updated);
    return structuredClone(updated);
  }

  async markCleaned(id: string, cleanedAt: string): Promise<void> {
    const row = this.rows.get(id);
    if (row && !row.cleanedAt) this.rows.set(id, { ...row, cleanedAt });
  }

  async close(): Promise<void> {}
}

class FakeRunner implements BuildRunner {
  starts = 0;
  cleanups = 0;
  inspection: KubernetesBuildInspection = { phase: "running" };

  async start(): Promise<void> { this.starts += 1; }
  async inspect(): Promise<KubernetesBuildInspection> { return this.inspection; }
  async cleanup(): Promise<void> { this.cleanups += 1; }
}

class FakeSigner {
  calls: string[] = [];
  materialCalls: string[] = [];
  failure?: Error;
  materialFailure?: Error;

  async verifyMaterial(image: string): Promise<void> {
    this.materialCalls.push(image);
    if (this.materialFailure) throw this.materialFailure;
  }

  async signAndVerify(image: string): Promise<void> {
    this.calls.push(image);
    if (this.failure) throw this.failure;
  }
}

function makeService(repository: MemoryRepository, runner: FakeRunner, signer = new FakeSigner()): BuildService {
  const catalog = new BuildCatalog({
    baseImages: [BASE_IMAGE],
    outputRepositories: [OUTPUT_REPOSITORY],
    packages: { "nginx-lab@1.2.3": { imageRef: PACKAGE_IMAGE, sourcePath: "/opt/codegate/package/", destination: "/opt/codegate/packages/nginx-lab/", runtimeKind: PACKAGE_RUNTIME_KIND } },
    artifacts: { [HEX_C]: { url: ARTIFACT_URL } },
  });
  return new BuildService({
    repository,
    runner,
    catalog,
    timeoutSeconds: 900,
    builderId: "https://codegate.ai/builders/environment-builder/v1",
    imageSigner: signer,
    now: () => new Date("2026-07-21T10:00:00.000Z"),
    idFactory: () => "11111111-1111-4111-8111-111111111111",
  });
}

test("creates once for an idempotent request", async () => {
  const repository = new MemoryRepository();
  const runner = new FakeRunner();
  const service = makeService(repository, runner);
  const first = await service.create(validBlueInput(), "request-12345");
  const replay = await service.create(validBlueInput(), "request-12345");
  assert.equal(first.id, replay.id);
  assert.equal(first.status, "running");
  assert.equal(runner.starts, 1);
});

test("persists a digest-pinned result, provenance, and runtime validation payload", async () => {
  const repository = new MemoryRepository();
  const runner = new FakeRunner();
  const signer = new FakeSigner();
  const service = makeService(repository, runner, signer);
  const created = await service.create(validBlueInput(), "request-12345");
  const digest = `sha256:${"d".repeat(64)}`;
  runner.inspection = { phase: "succeeded", log: `containerimage.digest=\"${digest}\"` };
  const completed = await service.get(created.id);
  assert.equal(completed.status, "succeeded");
  assert.equal(completed.imageRef, `${OUTPUT_REPOSITORY}:build-${created.id}`);
  assert.equal(completed.imageDigest, digest);
  assert.equal(completed.buildProvenance?.canonicalImage, `${OUTPUT_REPOSITORY}:build-${created.id}@${digest}`);
  assert.equal(completed.buildProvenance?.predicateType, "https://slsa.dev/provenance/v1");
  assert.equal(completed.buildProvenance?.runtimeContract.kind, "http-v1");
  assert.match(completed.buildProvenance?.runtimeContractDigest ?? "", /^sha256:[a-f0-9]{64}$/);
  assert.equal(completed.consumable?.target.validation.service.port, 8080);
  assert.equal(completed.consumable?.target.validation.telemetry?.events.length, 1);
  assert.deepEqual(completed.consumable?.target.expectedCves, ["CVE-2026-12345"]);
  assert.equal(completed.consumable?.validation.vulnerabilityProbes[0]?.cveId, "CVE-2026-12345");
  assert.deepEqual(completed.consumable?.scenario.mitreTechniques, ["T1110"]);
  assert.deepEqual(signer.calls, [`${OUTPUT_REPOSITORY}:build-${created.id}@${digest}`]);
  assert.deepEqual(signer.materialCalls.sort(), [BASE_IMAGE, PACKAGE_IMAGE].sort());
  if (!completed.consumable || !completed.imageRef || !completed.imageDigest) throw new Error("Completed build payload is missing");
  const runtimeInput = parseSandboxValidationRequest({
    image: `${completed.imageRef}@${completed.imageDigest}`,
    lab: {
      id: completed.labId,
      team: "blue",
      config: {
        target: completed.consumable.target,
        validation: completed.consumable.validation,
        questions: completed.consumable.questions,
        scenario: completed.consumable.scenario,
      },
    },
  }, ["registry.example.com"]);
  assert.equal(runtimeInput.functionalProbes[0]?.id, "health");
  assert.equal(runtimeInput.telemetryEvents[0]?.id, "auth-event-1");
  assert.equal(runtimeInput.mitreMappingsVerified, true);
  assert.equal(runner.cleanups, 1);
});

test("fails closed when the generated digest cannot be signed and verified", async () => {
  const repository = new MemoryRepository();
  const runner = new FakeRunner();
  const signer = new FakeSigner();
  signer.failure = new Error("registry signature unavailable");
  const service = makeService(repository, runner, signer);
  const created = await service.create(validBlueInput(), "request-12345");
  runner.inspection = { phase: "succeeded", log: `containerimage.digest="sha256:${"d".repeat(64)}"` };
  const completed = await service.get(created.id);
  assert.equal(completed.status, "failed");
  assert.equal(completed.failureCode, "build_signing_failed");
  assert.equal(completed.imageDigest, undefined);
});

test("rejects an unsigned base or component material before starting BuildKit", async () => {
  const repository = new MemoryRepository();
  const runner = new FakeRunner();
  const signer = new FakeSigner();
  signer.materialFailure = new Error("untrusted material");
  const service = makeService(repository, runner, signer);
  await assert.rejects(
    service.create(validBlueInput(), "request-12345"),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "image_material_untrusted",
  );
  assert.equal(runner.starts, 0);
  assert.equal(repository.rows.size, 0);
});

test("cancels and cleans an active build", async () => {
  const repository = new MemoryRepository();
  const runner = new FakeRunner();
  const service = makeService(repository, runner);
  const created = await service.create(validBlueInput(), "request-12345");
  const cancelled = await service.cancel(created.id);
  assert.equal(cancelled.status, "cancelled");
  assert.equal(runner.cleanups, 1);
});

test("returns API-compatible top-level failureCode for a failed Job", async () => {
  const repository = new MemoryRepository();
  const runner = new FakeRunner();
  const service = makeService(repository, runner);
  const created = await service.create(validBlueInput(), "request-12345");
  runner.inspection = { phase: "failed", reason: "BackoffLimitExceeded", log: "build failed" };
  const failed = await service.get(created.id);
  assert.equal(failed.status, "failed");
  assert.equal(failed.failureCode, "build_job_failed");
  assert.equal(failed.failure?.code, "build_job_failed");
  assert.equal(runner.cleanups, 1);
});
