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
  openAiApiKey: string;
  openAiModel: string;
  responsesEndpoint: string;
  generationTimeoutMs: number;
  reviewTimeoutMs: number;
  rubricTimeoutMs: number;
  maxConcurrency: number;
  rubrics: Readonly<Record<string, RubricDefinition>>;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;
const OFFICIAL_BASE_URL = "https://api.openai.com/v1";

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const internalToken = environment.MODEL_GATEWAY_INTERNAL_TOKEN ?? "";
  const openAiApiKey = environment.OPENAI_API_KEY ?? "";
  const openAiModel = environment.OPENAI_MODEL ?? "";
  if (internalToken.length < 32 || internalToken.length > 512 || /\s/.test(internalToken)) throw new Error("MODEL_GATEWAY_INTERNAL_TOKEN must contain 32-512 non-whitespace characters");
  if (openAiApiKey.length < 32 || openAiApiKey.length > 512 || /\s/.test(openAiApiKey)) throw new Error("OPENAI_API_KEY is required and malformed");
  if (!MODEL_ID.test(openAiModel) || openAiModel.startsWith("ft:")) throw new Error("OPENAI_MODEL must be a Structured Outputs-compatible non-fine-tuned model identifier");

  const baseUrl = (environment.OPENAI_BASE_URL ?? OFFICIAL_BASE_URL).replace(/\/$/, "");
  if (baseUrl !== OFFICIAL_BASE_URL) throw new Error("OPENAI_BASE_URL must be the official OpenAI API v1 endpoint");

  return {
    port: boundedInteger(environment.PORT, 9_010, 1, 65_535, "PORT"),
    internalToken,
    openAiApiKey,
    openAiModel,
    responsesEndpoint: `${baseUrl}/responses`,
    generationTimeoutMs: boundedInteger(environment.OPENAI_GENERATION_TIMEOUT_MS, 40_000, 5_000, 44_000, "OPENAI_GENERATION_TIMEOUT_MS"),
    reviewTimeoutMs: boundedInteger(environment.OPENAI_REVIEW_TIMEOUT_MS, 25_000, 5_000, 29_000, "OPENAI_REVIEW_TIMEOUT_MS"),
    rubricTimeoutMs: boundedInteger(environment.OPENAI_RUBRIC_TIMEOUT_MS, 9_000, 2_000, 11_000, "OPENAI_RUBRIC_TIMEOUT_MS"),
    maxConcurrency: boundedInteger(environment.MODEL_GATEWAY_MAX_CONCURRENCY, 8, 1, 64, "MODEL_GATEWAY_MAX_CONCURRENCY"),
    rubrics: Object.freeze(parseRubrics(environment.RUBRIC_CATALOG_JSON)),
  };
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
