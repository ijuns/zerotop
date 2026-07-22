import { randomUUID } from "node:crypto";

import type { BuildCatalog } from "./catalog.ts";
import type { BuildProvenance, BuildRecord, ConsumableBuildPayload, CreateBuildInput, PublicBuild } from "./contracts.ts";
import { BuilderError } from "./errors.ts";
import { extractImageDigest, type BuildRunner } from "./kubernetes.ts";
import type { BuildRepository } from "./repository.ts";
import { runtimeContractDigest } from "./runtime-contract.ts";
import type { ImageSigner } from "./signer.ts";
import { sha256Canonical } from "./validation.ts";

export interface BuildServiceOptions {
  repository: BuildRepository;
  runner: BuildRunner;
  catalog: BuildCatalog;
  timeoutSeconds: number;
  builderId: string;
  imageSigner: ImageSigner;
  now?: () => Date;
  idFactory?: () => string;
}

export class BuildService {
  private readonly repository: BuildRepository;
  private readonly runner: BuildRunner;
  private readonly catalog: BuildCatalog;
  private readonly timeoutSeconds: number;
  private readonly builderId: string;
  private readonly imageSigner: ImageSigner;
  private readonly now: () => Date;
  private readonly idFactory: () => string;
  private readonly reconciling = new Set<string>();
  private reconciliationRunning = false;

  constructor(options: BuildServiceOptions) {
    this.repository = options.repository;
    this.runner = options.runner;
    this.catalog = options.catalog;
    this.timeoutSeconds = options.timeoutSeconds;
    this.builderId = options.builderId;
    this.imageSigner = options.imageSigner;
    this.now = options.now ?? (() => new Date());
    this.idFactory = options.idFactory ?? randomUUID;
    if (!Number.isInteger(this.timeoutSeconds) || this.timeoutSeconds < 60 || this.timeoutSeconds > 3_600) throw new Error("Build timeout must be 60-3600 seconds");
    if (!/^https:\/\/[a-zA-Z0-9./:_-]{8,240}$/.test(this.builderId)) throw new Error("Builder ID must be a stable HTTPS URI");
  }

  async create(input: CreateBuildInput, idempotencyKey: string): Promise<PublicBuild> {
    validateIdempotencyKey(idempotencyKey);
    const resolution = this.catalog.resolve(input.spec);
    const materials = [input.spec.target.baseImage, ...resolution.resolvedPackages.map((item) => item.imageRef)];
    try {
      await Promise.all([...new Set(materials)].map((image) => this.imageSigner.verifyMaterial(image)));
    } catch {
      throw new BuilderError(422, "image_material_untrusted", "A selected base or component image failed signature verification");
    }
    const createdAt = this.now().toISOString();
    const id = this.idFactory();
    if (!/^[a-f0-9-]{36}$/i.test(id)) throw new Error("Build ID factory returned an invalid UUID");
    const requestDigest = sha256Canonical(input);
    const specDigest = sha256Canonical(input.spec);
    const compactId = id.replaceAll("-", "").slice(0, 24).toLowerCase();
    const record: BuildRecord = {
      id,
      labId: input.labId,
      labVersion: input.labVersion,
      requestedBy: input.requestedBy,
      idempotencyKey,
      requestDigest,
      specDigest,
      spec: input.spec,
      resolvedPackages: resolution.resolvedPackages,
      status: "queued",
      namespace: `cg-build-${compactId}`,
      jobName: "environment-build",
      createdAt,
      deadlineAt: new Date(Date.parse(createdAt) + this.timeoutSeconds * 1_000).toISOString(),
    };
    const result = await this.repository.create(record);
    if (!result.created) return toPublicBuild(result.record);
    try {
      await this.runner.start(result.record);
      const running = await this.repository.transition(result.record.id, {
        from: ["queued"],
        to: "running",
        startedAt: this.now().toISOString(),
        auditAction: "build.started",
      });
      return toPublicBuild(running ?? await this.required(result.record.id));
    } catch (error) {
      const failed = await this.fail(result.record, "build_start_failed", diagnostic(error));
      await this.cleanupWithRetry(result.record);
      return toPublicBuild(failed);
    }
  }

  async get(id: string): Promise<PublicBuild> {
    validateBuildId(id);
    let record = await this.required(id);
    if (record.status === "queued" || record.status === "running") {
      await this.reconcile(record);
      record = await this.required(id);
    }
    if (record.status !== "queued" && record.status !== "running" && !record.cleanedAt) {
      await this.cleanupWithRetry(record);
      record = await this.required(id);
    }
    return toPublicBuild(record);
  }

  async cancel(id: string): Promise<PublicBuild> {
    validateBuildId(id);
    const record = await this.required(id);
    if (record.status === "succeeded" || record.status === "failed" || record.status === "cancelled") {
      await this.cleanupWithRetry(record);
      return toPublicBuild(await this.required(id));
    }
    await this.cleanupWithRetry(record);
    const cancelled = await this.repository.transition(id, {
      from: ["queued", "running"],
      to: "cancelled",
      finishedAt: this.now().toISOString(),
      failureCode: "cancelled_by_request",
      failureDetail: "Build cancelled by the requesting platform service",
      auditAction: "build.cancelled",
    });
    return toPublicBuild(cancelled ?? await this.required(id));
  }

  async reconcileActive(): Promise<void> {
    if (this.reconciliationRunning) return;
    this.reconciliationRunning = true;
    try {
      const records = await this.repository.listActive(50);
      const cleanup = await this.repository.listCleanupPending(50);
      await Promise.allSettled([
        ...records.map((record) => this.reconcile(record)),
        ...cleanup.map((record) => this.cleanupWithRetry(record)),
      ]);
    } finally {
      this.reconciliationRunning = false;
    }
  }

  private async reconcile(record: BuildRecord): Promise<BuildRecord> {
    if (this.reconciling.has(record.id)) return this.required(record.id);
    this.reconciling.add(record.id);
    try {
      const current = await this.required(record.id);
      if (current.status !== "queued" && current.status !== "running") return current;
      if (this.now().getTime() >= Date.parse(current.deadlineAt)) {
        const failed = await this.fail(current, "build_timeout", "The controlled build exceeded its deadline");
        await this.cleanupWithRetry(current);
        return failed;
      }
      let inspection;
      try {
        inspection = await this.runner.inspect(current);
      } catch {
        return current;
      }
      if (current.status === "queued" && inspection.phase === "missing") {
        try {
          await this.runner.start(current);
          return await this.repository.transition(current.id, {
            from: ["queued"], to: "running", startedAt: this.now().toISOString(), auditAction: "build.recovered_and_started",
          }) ?? this.required(current.id);
        } catch (error) {
          const failed = await this.fail(current, "build_start_failed", diagnostic(error));
          await this.cleanupWithRetry(current);
          return failed;
        }
      }
      if ((inspection.phase === "pending" || inspection.phase === "running") && current.status === "queued") {
        return await this.repository.transition(current.id, {
          from: ["queued"], to: "running", startedAt: this.now().toISOString(), auditAction: "build.observed_running",
        }) ?? this.required(current.id);
      }
      if (inspection.phase === "missing") {
        const failed = await this.fail(current, "build_job_missing", "The Kubernetes build Job no longer exists");
        await this.cleanupWithRetry(current);
        return failed;
      }
      if (inspection.phase === "failed") {
        const failed = await this.fail(current, "build_job_failed", diagnostic(inspection.reason ?? inspection.log ?? "BuildKit Job failed"));
        await this.cleanupWithRetry(current);
        return failed;
      }
      if (inspection.phase === "succeeded") return this.complete(current, inspection.log ?? "");
      return current;
    } finally {
      this.reconciling.delete(record.id);
    }
  }

  private async complete(record: BuildRecord, log: string): Promise<BuildRecord> {
    let output;
    try {
      output = extractImageDigest(log, `${record.spec.target.outputRepository}:build-${record.id}`);
    } catch (error) {
      const failed = await this.fail(record, "build_digest_missing", diagnostic(error));
      await this.cleanupWithRetry(record);
      return failed;
    }
    try {
      await this.imageSigner.signAndVerify(`${output.imageRef}@${output.imageDigest}`);
    } catch (error) {
      const failed = await this.fail(record, "build_signing_failed", diagnostic(error));
      await this.cleanupWithRetry(record);
      return failed;
    }
    const finishedAt = this.now().toISOString();
    const provenance = makeProvenance(record, output.imageDigest, finishedAt, this.builderId);
    const consumable = makeConsumable(record, output.imageRef, output.imageDigest);
    const completed = await this.repository.transition(record.id, {
      from: ["queued", "running"],
      to: "succeeded",
      finishedAt,
      imageRef: output.imageRef,
      imageDigest: output.imageDigest,
      buildProvenance: provenance,
      consumable,
      auditAction: "build.succeeded",
      auditDetails: { imageRef: output.imageRef, imageDigest: output.imageDigest, specDigest: record.specDigest },
    }) ?? await this.required(record.id);
    await this.cleanupWithRetry(record);
    return completed;
  }

  private async fail(record: BuildRecord, code: string, detail: string): Promise<BuildRecord> {
    return await this.repository.transition(record.id, {
      from: ["queued", "running"],
      to: "failed",
      finishedAt: this.now().toISOString(),
      failureCode: code,
      failureDetail: detail,
      auditAction: "build.failed",
      auditDetails: { failureCode: code },
    }) ?? this.required(record.id);
  }

  private async cleanupWithRetry(record: BuildRecord): Promise<void> {
    if (record.cleanedAt) return;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        await this.runner.cleanup(record);
        await this.repository.markCleaned(record.id, this.now().toISOString());
        return;
      } catch {
        if (attempt < 2) await delay(100 * (attempt + 1));
      }
    }
  }

  private async required(id: string): Promise<BuildRecord> {
    const record = await this.repository.get(id);
    if (!record) throw new BuilderError(404, "build_not_found", "Build not found");
    return record;
  }
}

export function toPublicBuild(record: BuildRecord): PublicBuild {
  return {
    id: record.id,
    labId: record.labId,
    labVersion: record.labVersion,
    status: record.status,
    statusUrl: `/v1/builds/${record.id}`,
    ...(record.imageRef ? { imageRef: record.imageRef } : {}),
    ...(record.imageDigest ? { imageDigest: record.imageDigest } : {}),
    ...(record.buildProvenance ? { buildProvenance: record.buildProvenance } : {}),
    ...(record.consumable ? { consumable: record.consumable } : {}),
    ...(record.failureCode ? { failureCode: record.failureCode } : {}),
    ...(record.failureCode ? { failure: { code: record.failureCode, detail: record.failureDetail ?? "Build failed" } } : {}),
    createdAt: record.createdAt,
    ...(record.startedAt ? { startedAt: record.startedAt } : {}),
    ...(record.finishedAt ? { finishedAt: record.finishedAt } : {}),
  };
}

function makeProvenance(record: BuildRecord, imageDigest: string, finishedAt: string, builderId: string): BuildProvenance {
  const materialImages = [record.spec.target.baseImage, ...record.resolvedPackages.map((item) => item.imageRef)];
  return {
    schemaVersion: 1,
    predicateType: "https://slsa.dev/provenance/v1",
    buildType: "https://codegate.ai/buildtypes/declarative-environment/v1",
    builderId,
    buildId: record.id,
    invocationDigest: record.requestDigest,
    specDigest: record.specDigest,
    baseImage: record.spec.target.baseImage,
    runtimeContract: record.spec.target.runtimeContract,
    runtimeContractDigest: runtimeContractDigest(record.spec.target.runtimeContract),
    packageImages: record.resolvedPackages.map((item) => item.imageRef),
    artifactDigests: record.spec.target.artifacts.map((item) => `sha256:${item.sha256}`),
    outputRepository: record.spec.target.outputRepository,
    canonicalImage: `${record.spec.target.outputRepository}:build-${record.id}@${imageDigest}`,
    startedAt: record.startedAt ?? record.createdAt,
    finishedAt,
    hermetic: false,
    networkPolicy: "allowlisted-cidrs",
    parameters: { labId: record.labId, labVersion: record.labVersion, team: record.spec.team },
    subject: [{ name: record.spec.target.outputRepository, digest: { sha256: imageDigest.replace(/^sha256:/, "") } }],
    materials: [
      ...materialImages.map((image) => ({ uri: image.split("@", 1)[0] ?? image, digest: { sha256: image.split("@sha256:")[1] ?? "" } })),
      ...record.spec.target.artifacts.map((artifact) => ({ uri: artifact.url, digest: { sha256: artifact.sha256 } })),
    ],
  };
}

function makeConsumable(record: BuildRecord, imageRef: string, imageDigest: string): ConsumableBuildPayload {
  const target = record.spec.target;
  const validation = {
    service: target.service,
    functionalProbes: target.functionalProbes,
    vulnerabilityProbes: target.vulnerabilityProbes,
    ...(record.spec.telemetry ? { telemetry: record.spec.telemetry } : {}),
  };
  return {
    target: {
      ...target,
      imageRef,
      imageDigest,
      canonicalImage: `${imageRef}@${imageDigest}`,
      expectedCves: record.spec.source.cveIds,
      validation,
    },
    validation,
    scenario: record.spec.scenario,
    ...(record.spec.telemetry ? { telemetry: record.spec.telemetry } : {}),
    ...(record.spec.topology ? { topology: record.spec.topology } : {}),
    learning: record.spec.learning,
    questions: record.spec.questions,
    grading: record.spec.grading,
  };
}

function validateIdempotencyKey(value: string): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,127}$/.test(value)) throw new BuilderError(400, "invalid_idempotency_key", "Idempotency-Key must contain 8-128 safe characters");
}

function validateBuildId(value: string): void {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value)) throw new BuilderError(400, "invalid_build_id", "Build ID is invalid");
}

function diagnostic(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/[\r\n\t]+/g, " ").replace(/(?:token|password|authorization|auth)\s*[=:]\s*\S+/gi, "credential=[redacted]").slice(0, 1_000);
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
