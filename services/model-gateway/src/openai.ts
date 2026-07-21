import type { GatewayConfig } from "./config.ts";

export class ModelProviderError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(
    status: number,
    code: string,
    message: string,
  ) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface StructuredResponse {
  payload: Record<string, unknown>;
  responseId: string;
}

export interface StructuredRequest {
  schemaName: string;
  schema: Record<string, unknown>;
  instructions: string;
  input: Record<string, unknown>;
  maxOutputTokens: number;
  timeoutMs: number;
}

export class OpenAiResponsesClient {
  private readonly config: GatewayConfig;
  private readonly fetchImpl: typeof fetch;
  constructor(
    config: GatewayConfig,
    fetchImpl: typeof fetch = fetch,
  ) {
    this.config = config;
    this.fetchImpl = fetchImpl;
  }

  async createStructured(request: StructuredRequest): Promise<StructuredResponse> {
    const response = await this.fetchImpl(this.config.responsesEndpoint, {
      method: "POST",
      redirect: "error",
      headers: {
        authorization: `Bearer ${this.config.openAiApiKey}`,
        "content-type": "application/json",
        accept: "application/json",
        "user-agent": "CODEGATE-Model-Gateway/1.0",
      },
      body: JSON.stringify({
        model: this.config.openAiModel,
        instructions: request.instructions,
        input: JSON.stringify(request.input),
        text: {
          format: {
            type: "json_schema",
            name: request.schemaName,
            strict: true,
            schema: request.schema,
          },
        },
        max_output_tokens: request.maxOutputTokens,
        store: false,
        parallel_tool_calls: false,
      }),
      signal: AbortSignal.timeout(request.timeoutMs),
    }).catch((error: unknown) => {
      if (error instanceof ModelProviderError) throw error;
      throw new ModelProviderError(503, "model_provider_unavailable", "The model provider is unavailable");
    });

    if (!response.ok) {
      await discardLimited(response, 64_000);
      const status = response.status === 429 ? 429 : response.status >= 500 ? 503 : 502;
      throw new ModelProviderError(status, "model_provider_rejected", `The model provider returned HTTP ${response.status}`);
    }
    const raw = await readLimited(response, 2_000_000);
    let value: unknown;
    try {
      value = JSON.parse(raw) as unknown;
    } catch {
      throw new ModelProviderError(502, "model_response_malformed", "The model provider returned malformed JSON");
    }
    const root = asRecord(value);
    const responseId = string(root.id, "model response id", 8, 200);
    if (root.status !== "completed") throw new ModelProviderError(502, "model_response_incomplete", "The model provider response was incomplete");
    const output = Array.isArray(root.output) ? root.output : [];
    const messages = output.filter((item) => asRecord(item).type === "message").map(asRecord);
    if (messages.length !== 1 || messages[0]?.status !== "completed") throw new ModelProviderError(502, "model_response_invalid", "The model provider returned no completed message");
    const content = Array.isArray(messages[0].content) ? messages[0].content : [];
    if (content.some((item) => asRecord(item).type === "refusal")) throw new ModelProviderError(422, "model_refused", "The model provider refused the request");
    const outputText = content.filter((item) => asRecord(item).type === "output_text").map(asRecord);
    if (content.length !== 1 || outputText.length !== 1 || typeof outputText[0]?.text !== "string" || Buffer.byteLength(outputText[0].text, "utf8") > 1_000_000) throw new ModelProviderError(502, "model_response_invalid", "The model provider returned invalid structured content");
    let payload: unknown;
    try {
      payload = JSON.parse(outputText[0].text) as unknown;
    } catch {
      throw new ModelProviderError(502, "model_output_malformed", "The model provider output was not JSON");
    }
    return { payload: asRecord(payload), responseId };
  }
}

async function readLimited(response: Response, maximumBytes: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel();
      throw new ModelProviderError(502, "model_response_too_large", "The model provider response exceeded its limit");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function discardLimited(response: Response, maximumBytes: number): Promise<void> {
  try {
    await readLimited(response, maximumBytes);
  } catch {
    // Provider error bodies are never propagated or logged.
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ModelProviderError(502, "model_response_invalid", "The model provider returned an invalid object");
  return value as Record<string, unknown>;
}

function string(value: unknown, name: string, minimum: number, maximum: number): string {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum) throw new ModelProviderError(502, "model_response_invalid", `${name} is invalid`);
  return value;
}
