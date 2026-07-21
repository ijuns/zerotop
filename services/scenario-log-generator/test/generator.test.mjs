import assert from "node:assert/strict";
import test from "node:test";

import {
  blueTelemetryGeneration,
  expandBlueTelemetryEvents,
} from "../../api/src/blue-telemetry.ts";

const anchor = "2026-07-22T05:00:00.000Z";

test("expands the PowerShell RCE scenario into deterministic signal and background telemetry", () => {
  const lab = { id: "lab-powershell", name: "의심스러운 PowerShell 활동 조사" };
  const config = {
    scenario: {
      objective: "공개 서비스 RCE 이후 PowerShell로 개인정보를 수집하고 외부로 반출",
      mitreTechniques: ["T1190", "T1059.001", "T1005", "T1560.001", "T1041"],
    },
  };
  const generation = blueTelemetryGeneration(lab, config, { totalEvents: 1_200, timeRangeMinutes: 60 }, anchor);
  const seed = [{
    id: "blue-q1-elk-evidence",
    document: {
      "@timestamp": "2020-01-01T00:00:00.000Z",
      event: { category: ["authentication"], dataset: "windows.security" },
      source: { ip: "192.0.2.44" },
      threat: { technique: { id: ["T1078"] } },
    },
  }];

  const first = expandBlueTelemetryEvents(seed, generation);
  const second = expandBlueTelemetryEvents(seed, generation);
  assert.deepEqual(first, second);
  assert.equal(first.length, 1_200);
  assert.equal(new Set(first.map((event) => event.id)).size, 1_200);
  assert.ok(first.some((event) => event.id === "blue-q1-elk-evidence"));
  for (const id of [
    "signal-web-rce-probe",
    "signal-webshell-powershell",
    "signal-powershell-recon",
    "signal-sensitive-file-read",
    "signal-archive-created",
    "signal-outbound-exfiltration",
  ]) assert.ok(first.some((event) => event.id === id), `${id} must be present`);

  const categories = new Set(first.flatMap((event) => {
    const value = event.document.event;
    return typeof value === "object" && value !== null && Array.isArray(value.category)
      ? value.category
      : [];
  }));
  for (const category of ["authentication", "process", "network", "file", "web"]) {
    assert.ok(categories.has(category), `${category} background family must be present`);
  }
  assert.doesNotMatch(JSON.stringify(first), /"(?:answer|answerKey|correctAnswer|solution|flag)"\s*:/i);
  const earliest = Date.parse(String(first[0]?.document["@timestamp"]));
  const latest = Date.parse(String(first.at(-1)?.document["@timestamp"]));
  assert.ok(earliest >= Date.parse(anchor) - 60 * 60_000);
  assert.ok(latest <= Date.parse(anchor));
});

test("generic profile preserves scenario-specific AI seed events while adding bounded background activity", () => {
  const generation = blueTelemetryGeneration(
    { id: "lab-generic", name: "Linux 인증 조사" },
    { scenario: { objective: "SSH 계정 오용 탐지", mitreTechniques: ["T1078"] } },
    { profile: "generic_endpoint_activity", totalEvents: 350, timeRangeMinutes: 30, seed: "generic-seed" },
    anchor,
  );
  const events = expandBlueTelemetryEvents([{
    id: "ssh-auth-signal",
    document: {
      "@timestamp": "2021-01-01T00:00:00.000Z",
      event: { category: ["authentication"], dataset: "system.auth" },
      source: { ip: "198.51.100.25" },
      threat: { technique: { id: ["T1078"] } },
    },
  }], generation);

  assert.equal(events.length, 350);
  assert.ok(events.some((event) => event.id === "ssh-auth-signal"));
  assert.equal(events.some((event) => event.id === "signal-webshell-powershell"), false);
});

test("rejects unbounded generation counts", () => {
  assert.throws(() => blueTelemetryGeneration(
    { id: "lab" },
    { scenario: {} },
    { totalEvents: 5_001 },
    anchor,
  ), /between 100 and 5000/);
});
