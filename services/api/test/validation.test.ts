import assert from "node:assert/strict";
import test from "node:test";

import { evaluateLab } from "../src/validation.ts";

test("automatic validation is deterministic for a valid blue-team lab", () => {
  const lab = {
    id: "lab_deterministic",
    teamType: "blue",
    environment: "ubuntu",
    questionTypes: ["elk_search", "mitre_attack"],
    config: {
      telemetry: { elkEnabled: true, indexPattern: "codegate-logs-*" },
      safety: { payloadMasked: true, allowLiveMalware: false },
      scenario: { mitreTechniques: ["T1078", "T1059.001"] },
    },
  };

  const first = evaluateLab(lab);
  const second = evaluateLab(lab);
  assert.deepEqual(second, first);
  assert.equal(first.decision, "pass");
  assert.equal(first.status, "validated");
  assert.ok(first.evidence.every((item) => item.outcome === "pass"));
});

test("unsafe generated content is deterministically quarantined", () => {
  const result = evaluateLab({
    id: "lab_unsafe",
    teamType: "red",
    environment: "kali",
    questionTypes: ["free_text", "mitre_attack"],
    config: {
      telemetry: { elkEnabled: false, indexPattern: "codegate-logs-*" },
      safety: { payloadMasked: false, allowLiveMalware: true },
      scenario: { mitreTechniques: ["T1190"] },
    },
  });

  assert.equal(result.decision, "quarantine");
  assert.equal(result.status, "quarantined");
  assert.equal(
    result.evidence.find((item) => item.checkName === "payload_safety")?.outcome,
    "fail",
  );
});
