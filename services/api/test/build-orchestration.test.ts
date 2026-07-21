import assert from "node:assert/strict";
import test from "node:test";
import { createApplication } from "../src/app.ts";

test("generated Labs persist hidden build specs and refresh a successful immutable target", async () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const buildSpec = {
    schemaVersion: 1,
    team: "red",
    source: { promptDigest: `sha256:${"b".repeat(64)}`, cveIds: ["CVE-2025-12345"] },
    target: { outputRepository: "registry.local/ranges/generated" },
  };
  let statusRequests = 0;
  const application = createApplication({
    authMode: "dev",
    repositoryMode: "sqlite",
    databasePath: ":memory:",
    labGenerator: {
      generate(input) {
        return {
          ...input,
          buildSpec,
          config: {
            ...input.config,
            learning: {
              title: "Generated CVE range",
              summary: "Rich learner-facing curriculum",
              prerequisites: ["HTTP fundamentals"],
              objectives: ["Preserve the validated learning objective"],
              sections: [{ id: "context", title: "Threat context", bodyMarkdown: "Learner-facing body that must survive the environment build." }],
            },
            scenario: {
              summary: "Rich scenario summary",
              logSources: ["nginx.access"],
              attackChain: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" }],
            },
            questions: [{ id: "red-q1", type: "single_choice", prompt: "Choose the safe action", points: 30, options: [{ id: "a", label: "Inspect" }, { id: "b", label: "Escape" }] }],
          },
        };
      },
    },
    environmentBuilder: {
      async start() {
        return { id: "build-1", status: "queued", createdAt: "2026-07-21T00:00:00.000Z" };
      },
      async get() {
        statusRequests += 1;
        return {
          id: "build-1",
          status: "succeeded",
          createdAt: "2026-07-21T00:00:00.000Z",
          updatedAt: "2026-07-21T00:01:00.000Z",
          imageRef: "registry.local/ranges/generated:build-1",
          imageDigest: digest,
          buildProvenance: { builder: "rootless-buildkit", reproducible: true },
          consumable: {
            target: {
              expectedCves: ["CVE-2025-12345"],
              service: { port: 8080, protocol: "http" },
              runtimeContract: {
                kind: "http-v1", uid: 65532, gid: 65532, protocol: "http", port: 8080,
                writablePaths: ["/tmp"], readOnlyRootFilesystem: true, bindAddress: "0.0.0.0",
                healthPath: "/health", fingerprintPath: "/version",
              },
              validation: {
                service: { port: 8080, protocol: "http" },
                functionalProbes: [{ id: "health", kind: "http", method: "GET", path: "/health", expectedStatuses: [200], bodyIncludes: ["ready"] }],
                vulnerabilityProbes: [{ id: "cve", cveId: "CVE-2025-12345", kind: "http", method: "GET", path: "/version", expectedStatuses: [200], bodyIncludes: ["vulnerable"] }],
              },
            },
            learning: {
              title: "Generated CVE range",
              summary: "Build projection",
              sections: [{ id: "context", title: "Threat context", markdown: "Builder projection body" }],
            },
            scenario: { summary: "Build projection", mitreTechniques: ["T1190"] },
            questions: [{ id: "builder-q", type: "single_choice", prompt: "Builder projection", points: 1 }],
          },
        };
      },
      async cancel() {},
    },
  });
  await new Promise<void>((resolve, reject) => {
    application.server.once("error", reject);
    application.server.listen(0, "127.0.0.1", resolve);
  });
  const address = application.server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const generated = await fetch(`${base}/v1/labs/generate`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-user-id": "user_dev", "idempotency-key": "generate-build-test" },
      body: JSON.stringify({
        title: "Generated CVE range",
        prompt: "Build an isolated target and validate the intended CVE fingerprint.",
        team: "red",
        desktopImage: "kali",
        accessMethod: "browser_desktop",
        questionTypes: ["single_choice"],
        cveIds: ["CVE-2025-12345"],
      }),
    });
    assert.equal(generated.status, 201);
    const firstPayload = await generated.json() as { data: { lab: Record<string, unknown> } };
    const firstConfig = firstPayload.data.lab.config as Record<string, unknown>;
    assert.equal((firstConfig.builder as Record<string, unknown>).status, "queued");
    assert.equal("builderSpec" in firstConfig, false);

    const detail = await fetch(`${base}/v1/labs/${encodeURIComponent(String(firstPayload.data.lab.id))}`, {
      headers: { "x-user-id": "user_dev" },
    });
    assert.equal(detail.status, 200);
    const detailPayload = await detail.json() as { data: { lab: Record<string, unknown> } };
    const config = detailPayload.data.lab.config as Record<string, unknown>;
    assert.equal((config.builder as Record<string, unknown>).status, "succeeded");
    assert.equal((config.target as Record<string, unknown>).imageDigest, digest);
    const learning = detailPayload.data.lab.learning as Record<string, unknown>;
    assert.deepEqual(learning.objectives, ["Preserve the validated learning objective"]);
    assert.deepEqual(learning.prerequisites, ["HTTP fundamentals"]);
    assert.equal(((learning.sections as Array<Record<string, unknown>>)[0]).bodyMarkdown, "Learner-facing body that must survive the environment build.");
    const scenario = detailPayload.data.lab.scenario as Record<string, unknown>;
    assert.equal(scenario.summary, "Rich scenario summary");
    assert.deepEqual(scenario.logSources, ["nginx.access"]);
    assert.equal(((detailPayload.data.lab.questions as Array<Record<string, unknown>>)[0]).id, "red-q1");
    assert.equal("builderSpec" in config, false);
    assert.equal(statusRequests, 1);
    assert.deepEqual(await application.repository.getLabBuildSpec("user_dev", String(firstPayload.data.lab.id)), buildSpec);
  } finally {
    await application.close();
  }
});
