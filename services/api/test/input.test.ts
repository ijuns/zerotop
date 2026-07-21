import assert from "node:assert/strict";
import { test } from "node:test";

import { ApiError } from "../src/errors.ts";
import { normalizeLabGeneration } from "../src/input.ts";

function redRequest(overrides: Record<string, unknown> = {}) {
  return {
    title: "CVE 기반 침투 훈련",
    team: "red",
    desktopImage: "kali",
    accessMethod: "both",
    questionTypes: ["single_choice", "multiple_choice", "free_text", "mitre_attack"],
    ...overrides,
  };
}

test("CVE IDs alone synthesize a neutral Korean prompt for downstream use", () => {
  const normalized = normalizeLabGeneration(redRequest({
    prompt: "   ",
    cveIds: ["cve-2024-12345", "CVE-2024-12345", "CVE-2023-44487"],
  }));

  assert.deepEqual(normalized.cveIds, ["CVE-2024-12345", "CVE-2023-44487"]);
  assert.equal(
    normalized.prompt,
    "CVE-2024-12345, CVE-2023-44487 취약점의 적용 조건과 영향 범위, 방어 관측 지점을 격리된 환경에서 안전하게 분석합니다.",
  );
  assert.equal(
    (normalized.config.scenario as Record<string, unknown>).objective,
    normalized.prompt,
  );
});

test("generation intent requires at least a prompt or one CVE ID", () => {
  assert.throws(
    () => normalizeLabGeneration(redRequest()),
    (error) => error instanceof ApiError &&
      error.code === "PROMPT_OR_CVE_REQUIRED" &&
      error.status === 400,
  );
});

test("a supplied prompt keeps the 10 character minimum even with CVE IDs", () => {
  assert.throws(
    () => normalizeLabGeneration(redRequest({
      prompt: "짧은 목표",
      cveIds: ["CVE-2024-12345"],
    })),
    (error) => error instanceof ApiError &&
      error.code === "INVALID_PROMPT" &&
      error.status === 400,
  );
});

test("a valid prompt remains unchanged without CVE IDs", () => {
  const normalized = normalizeLabGeneration(redRequest({
    prompt: "격리된 웹 환경에서 안전한 침투 흐름을 분석합니다.",
  }));

  assert.equal(normalized.prompt, "격리된 웹 환경에서 안전한 침투 흐름을 분석합니다.");
  assert.deepEqual(normalized.cveIds, []);
});
