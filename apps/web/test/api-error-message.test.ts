import assert from "node:assert/strict";
import test from "node:test";

import { ApiError, errorMessage } from "../lib/api.ts";

test("shows whitelisted AI debug fields with the user-facing API error", () => {
  const error = new ApiError("Claude 생성 서비스가 요청을 처리하지 못했습니다.", 502, "AI_UPSTREAM_ERROR", {
    debug: {
      stage: "generation",
      providerStage: "anthropic",
      upstreamStatus: 504,
      upstreamCode: "model_response_invalid",
      upstreamMessage: "Anthropic response exceeded the configured timeout",
      providerStatus: 400,
      providerErrorType: "invalid_request_error",
      providerRequestId: "req_01ABC",
      providerResponseId: "msg_01ABC",
      providerMessage: "The request exceeded the provider deadline",
      generationAttempts: 2,
      payloadBytes: 65432,
      payloadDigest: "sha256:abcdef0123456789",
      parseKind: "syntax_error",
      parseOffset: 321,
      timeoutMs: 1_200_000,
      prompt: "must never be rendered",
      apiKey: "must never be rendered",
      rawBody: "must never be rendered",
      stack: "must never be rendered",
    },
  });

  const message = errorMessage(error);
  assert.match(message, /status=502/);
  assert.match(message, /code=AI_UPSTREAM_ERROR/);
  assert.match(message, /stage=generation/);
  assert.match(message, /providerStage=anthropic/);
  assert.match(message, /upstreamStatus=504/);
  assert.match(message, /upstreamCode=model_response_invalid/);
  assert.match(message, /upstreamMessage=Anthropic response exceeded/);
  assert.match(message, /providerStatus=400/);
  assert.match(message, /providerErrorType=invalid_request_error/);
  assert.match(message, /providerRequestId=req_01ABC/);
  assert.match(message, /providerResponseId=msg_01ABC/);
  assert.match(message, /providerMessage=The request exceeded/);
  assert.match(message, /generationAttempts=2/);
  assert.match(message, /payloadBytes=65432/);
  assert.match(message, /payloadDigest=sha256:abcdef0123456789/);
  assert.match(message, /parseKind=syntax_error/);
  assert.match(message, /parseOffset=321/);
  assert.match(message, /timeoutMs=1200000/);
  assert.doesNotMatch(message, /must never be rendered/);
  assert.doesNotMatch(message, /apiKey|rawBody|stack/);
});

test("does not expose arbitrary details when debug is absent or not a safe object", () => {
  const secret = "sk-ant-secret-value";
  assert.equal(
    errorMessage(new ApiError("요청 실패", 502, "AI_UPSTREAM_ERROR", { rawBody: secret })),
    "요청 실패",
  );
  assert.equal(
    errorMessage(new ApiError("요청 실패", 502, "AI_UPSTREAM_ERROR", { debug: [secret] })),
    "요청 실패",
  );
});

test("normalizes control characters and bounds provider debug values", () => {
  const error = new ApiError("요청 실패", 504, "AI_TIMEOUT", {
    debug: {
      stage: "generation\nphase",
      providerRequestId: `req_${"x".repeat(300)}`,
    },
  });

  const message = errorMessage(error);
  assert.match(message, /stage=generation phase/);
  assert.equal(message.split("\n").length, 2);
  assert.ok(message.length < 300);
});
