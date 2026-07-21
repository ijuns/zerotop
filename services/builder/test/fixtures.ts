import type { CreateBuildInput } from "../src/contracts.ts";

export const HEX_A = "a".repeat(64);
export const HEX_B = "b".repeat(64);
export const HEX_C = "c".repeat(64);
export const BASE_IMAGE = `registry.example.com/containerdisks/ubuntu@sha256:${HEX_A}`;
export const PACKAGE_IMAGE = `registry.example.com/catalog/nginx@sha256:${HEX_B}`;
export const OUTPUT_REPOSITORY = "registry.example.com/codegate/targets";
export const ARTIFACT_URL = "https://artifacts.example.com/fixtures/auth-events.ndjson";
export const PACKAGE_RUNTIME_KIND = "signed-node-handler-v1" as const;

export function validBlueInput(): CreateBuildInput {
  return {
    labId: "lab-cve-2026-12345",
    labVersion: 3,
    requestedBy: "user-123",
    spec: {
      schemaVersion: 1,
      team: "blue",
      source: { promptDigest: `sha256:${HEX_C}`, cveIds: ["CVE-2026-12345"] },
      scenario: { summary: "Investigate controlled authentication abuse.", mitreTechniques: ["T1110"] },
      target: {
        name: "Authentication telemetry range",
        baseImage: BASE_IMAGE,
        outputRepository: OUTPUT_REPOSITORY,
        service: { port: 8080, protocol: "http" },
        runtimeContract: {
          kind: "http-v1",
          uid: 65532,
          gid: 65532,
          protocol: "http",
          port: 8080,
          writablePaths: ["/tmp"],
          readOnlyRootFilesystem: true,
          bindAddress: "0.0.0.0",
          healthPath: "/health",
          fingerprintPath: "/version",
        },
        packages: [{ name: "nginx-lab", version: "1.2.3" }],
        artifacts: [{ url: ARTIFACT_URL, sha256: HEX_C, destination: "/opt/codegate/artifacts/auth-events.ndjson" }],
        functionalProbes: [{ id: "health", kind: "http", method: "GET", path: "/health", expectedStatuses: [200], bodyIncludes: ["healthy"] }],
        vulnerabilityProbes: [{
          id: "cve-signal",
          cveId: "CVE-2026-12345",
          kind: "http",
          method: "HEAD",
          path: "/vulnerable",
          expectedStatuses: [500],
          bodyIncludes: [],
        }],
      },
      telemetry: {
        fixtures: [{ eventId: "auth-event-fixture", index: "logs-auth-default", artifactSha256: HEX_C, mitreTechniqueIds: ["T1110"] }],
        events: [{
          id: "auth-event-1",
          document: {
            "@timestamp": "2026-07-21T10:00:00.000Z",
            event: { kind: "alert", category: ["authentication"] },
            threat: { technique: { id: ["T1110"] } },
            source: { ip: "198.51.100.10" },
          },
        }],
      },
      learning: {
        title: "Detect authentication abuse",
        summary: "Use ELK evidence and ATT&CK mapping to investigate a controlled authentication event.",
        sections: [{ id: "intro", title: "Introduction", markdown: "Search the per-run index and correlate the event." }],
      },
      questions: [
        { id: "q-elk", type: "elk_search", prompt: "Find the source address in the authentication event.", points: 50 },
        { id: "q-mitre", type: "mitre_attack", prompt: "Map the event to the relevant ATT&CK technique.", points: 50 },
      ],
      grading: {
        hiddenRefs: [
          { questionId: "q-elk", refId: "grading://labs/auth/q-elk", rubricDigest: `sha256:${HEX_A}` },
          { questionId: "q-mitre", refId: "grading://labs/auth/q-mitre", rubricDigest: `sha256:${HEX_B}` },
        ],
      },
    },
  };
}
