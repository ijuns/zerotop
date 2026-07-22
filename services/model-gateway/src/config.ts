export interface RubricCriterion {
  id: string;
  description: string;
  weight: number;
}

export interface RubricDefinition {
  policyVersion: string;
  passThreshold: number;
  criteria: RubricCriterion[];
}

export interface GatewayConfig {
  port: number;
  internalToken: string;
  provider: "anthropic";
  providerApiKey: string;
  providerModel: string;
  providerEndpoint: string;
  anthropicVersion: string;
  generationTimeoutMs: number;
  generationMaxAttempts: number;
  captureGenerationRawResponse: boolean;
  reviewTimeoutMs: number;
  rubricTimeoutMs: number;
  maxConcurrency: number;
  rubrics: Readonly<Record<string, RubricDefinition>>;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;
const OFFICIAL_ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1";
const API_VERSION = /^\d{4}-\d{2}-\d{2}$/;

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const internalToken = environment.MODEL_GATEWAY_INTERNAL_TOKEN ?? "";
  if (internalToken.length < 32 || internalToken.length > 512 || /\s/.test(internalToken)) throw new Error("MODEL_GATEWAY_INTERNAL_TOKEN must contain 32-512 non-whitespace characters");
  requireAnthropicProvider(environment.MODEL_PROVIDER);
  const providerConfig = anthropicConfig(environment);

  return {
    port: boundedInteger(environment.PORT, 9_010, 1, 65_535, "PORT"),
    internalToken,
    provider: "anthropic",
    ...providerConfig,
    generationTimeoutMs: providerTimeout(environment, "GENERATION", 1_200_000, 5_000, 1_200_000),
    generationMaxAttempts: boundedInteger(environment.MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS, 1, 1, 2, "MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS"),
    captureGenerationRawResponse: generationRawResponseCapture(environment.MODEL_GATEWAY_DEBUG_RAW_RESPONSE_CAPTURE),
    reviewTimeoutMs: providerTimeout(environment, "REVIEW", 25_000, 5_000, 29_000),
    rubricTimeoutMs: providerTimeout(environment, "RUBRIC", 9_000, 2_000, 11_000),
    maxConcurrency: boundedInteger(environment.MODEL_GATEWAY_MAX_CONCURRENCY, 8, 1, 64, "MODEL_GATEWAY_MAX_CONCURRENCY"),
    rubrics: Object.freeze(parseRubrics(environment.RUBRIC_CATALOG_JSON)),
  };
}

function generationRawResponseCapture(raw: string | undefined): boolean {
  if (raw === undefined) return false;
  if (raw === "local-explicit") return true;
  throw new Error("MODEL_GATEWAY_DEBUG_RAW_RESPONSE_CAPTURE must be unset or exactly local-explicit");
}

function requireAnthropicProvider(raw: string | undefined): void {
  if (raw !== undefined && raw.toLowerCase() !== "anthropic") throw new Error("MODEL_PROVIDER must be anthropic when set");
}

function anthropicConfig(environment: NodeJS.ProcessEnv): Pick<GatewayConfig, "providerApiKey" | "providerModel" | "providerEndpoint" | "anthropicVersion"> {
  const apiKey = requiredSecret(environment.ANTHROPIC_API_KEY, "ANTHROPIC_API_KEY");
  const model = environment.ANTHROPIC_MODEL ?? "";
  if (!MODEL_ID.test(model)) throw new Error("ANTHROPIC_MODEL must be a Structured Outputs-compatible model identifier");
  const baseUrl = officialBaseUrl(environment.ANTHROPIC_BASE_URL, OFFICIAL_ANTHROPIC_BASE_URL, "ANTHROPIC_BASE_URL", "Anthropic");
  const version = environment.ANTHROPIC_VERSION ?? "2023-06-01";
  if (!API_VERSION.test(version)) throw new Error("ANTHROPIC_VERSION must use YYYY-MM-DD format");
  return { providerApiKey: apiKey, providerModel: model, providerEndpoint: `${baseUrl}/messages`, anthropicVersion: version };
}

function requiredSecret(raw: string | undefined, name: string): string {
  const value = raw ?? "";
  if (value.length < 32 || value.length > 512 || /\s/.test(value)) throw new Error(`${name} is required and malformed`);
  return value;
}

function officialBaseUrl(raw: string | undefined, fallback: string, name: string, provider: string): string {
  const value = (raw ?? fallback).replace(/\/$/, "");
  if (value !== fallback) throw new Error(`${name} must be the official ${provider} API v1 endpoint`);
  return value;
}

function providerTimeout(environment: NodeJS.ProcessEnv, operation: "GENERATION" | "REVIEW" | "RUBRIC", fallback: number, minimum: number, maximum: number): number {
  const neutralName = `MODEL_GATEWAY_${operation}_TIMEOUT_MS`;
  const legacyName = `ANTHROPIC_${operation}_TIMEOUT_MS`;
  return boundedInteger(environment[neutralName] ?? environment[legacyName], fallback, minimum, maximum, neutralName);
}

function parseRubrics(raw: string | undefined): Record<string, RubricDefinition> {
  if (!raw || Buffer.byteLength(raw, "utf8") > 256_000) throw new Error("RUBRIC_CATALOG_JSON is required and bounded");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("RUBRIC_CATALOG_JSON is invalid JSON");
  }
  if (!record(parsed) || Object.keys(parsed).length === 0 || Object.keys(parsed).length > 100) throw new Error("RUBRIC_CATALOG_JSON must be a non-empty object");
  const result: Record<string, RubricDefinition> = {};
  for (const [rubricId, value] of Object.entries(parsed)) {
    if (!IDENTIFIER.test(rubricId) || !record(value) || !exactKeys(value, ["policyVersion", "passThreshold", "criteria"])) throw new Error(`Rubric ${rubricId} is invalid`);
    const threshold = value.passThreshold;
    if (typeof value.policyVersion !== "string" || !IDENTIFIER.test(value.policyVersion) || typeof threshold !== "number" || !Number.isFinite(threshold) || threshold < 0 || threshold > 1 || !Array.isArray(value.criteria) || value.criteria.length < 1 || value.criteria.length > 20) throw new Error(`Rubric ${rubricId} is invalid`);
    const criteria = value.criteria.map((item, index) => {
      if (!record(item) || !exactKeys(item, ["id", "description", "weight"]) || typeof item.id !== "string" || !IDENTIFIER.test(item.id) || typeof item.description !== "string" || item.description.length < 10 || item.description.length > 1_000 || typeof item.weight !== "number" || !Number.isFinite(item.weight) || item.weight <= 0 || item.weight > 1) throw new Error(`Rubric ${rubricId} criterion ${index} is invalid`);
      return { id: item.id, description: item.description, weight: item.weight };
    });
    if (new Set(criteria.map((item) => item.id)).size !== criteria.length || Math.abs(criteria.reduce((sum, item) => sum + item.weight, 0) - 1) > 0.000_001) throw new Error(`Rubric ${rubricId} weights must be unique and sum to 1`);
    result[rubricId] = { policyVersion: value.policyVersion, passThreshold: threshold, criteria };
  }
  return result;
}

function boundedInteger(raw: string | undefined, fallback: number, minimum: number, maximum: number, name: string): number {
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${name} is invalid`);
  return value;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  return Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");
}
