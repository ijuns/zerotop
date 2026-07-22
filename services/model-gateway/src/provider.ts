export class ModelProviderError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: Readonly<Record<string, string | number>>;
  constructor(
    status: number,
    code: string,
    message: string,
    details?: Readonly<Record<string, string | number>>,
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
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
