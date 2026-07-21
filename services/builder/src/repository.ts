import type { BuildProvenance, BuildRecord, BuildStatus, ConsumableBuildPayload } from "./contracts.ts";

export interface CreateRecordResult {
  record: BuildRecord;
  created: boolean;
}

export interface BuildTransition {
  from: BuildStatus[];
  to: BuildStatus;
  startedAt?: string;
  finishedAt?: string;
  imageRef?: string;
  imageDigest?: string;
  buildProvenance?: BuildProvenance;
  consumable?: ConsumableBuildPayload;
  failureCode?: string;
  failureDetail?: string;
  auditAction: string;
  auditDetails?: Record<string, unknown>;
}

export interface BuildRepository {
  migrate(): Promise<void>;
  create(record: BuildRecord): Promise<CreateRecordResult>;
  get(id: string): Promise<BuildRecord | null>;
  listActive(limit: number): Promise<BuildRecord[]>;
  listCleanupPending(limit: number): Promise<BuildRecord[]>;
  transition(id: string, transition: BuildTransition): Promise<BuildRecord | null>;
  markCleaned(id: string, cleanedAt: string): Promise<void>;
  close(): Promise<void>;
}
