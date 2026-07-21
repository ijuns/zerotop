import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { COMPONENT_WORKER_RESOURCE_LIMITS, createTargetServer, loadComponentCatalog } from "../src/server.mjs";

test("bounds curated component workers below the pod-level limit", () => {
  assert.deepEqual(COMPONENT_WORKER_RESOURCE_LIMITS, {
    maxOldGenerationSizeMb: 32,
    maxYoungGenerationSizeMb: 8,
    stackSizeMb: 2,
  });
});

async function fixture(manifest, artifact = "approved artifact\n") {
  const root = await mkdtemp(join(tmpdir(), "codegate-target-test-"));
  const packageRoot = join(root, "packages");
  const artifactRoot = join(root, "artifacts");
  await mkdir(join(packageRoot, "identity-chain"), { recursive: true });
  await mkdir(artifactRoot, { recursive: true });
  await writeFile(join(packageRoot, "identity-chain", "component.json"), JSON.stringify(manifest));
  await writeFile(join(artifactRoot, "evidence.json"), artifact);
  const policyPath = join(root, "component-policy.json");
  await writeFile(policyPath, JSON.stringify({
    schemaVersion: "codegate-component-policy/v1",
    components: [{ componentId: manifest.componentId, runtimeKind: manifest.kind }],
  }));
  return { packageRoot, artifactRoot, policyPath };
}

function validManifest() {
  return {
    schemaVersion: "codegate-component/v1",
    kind: "declarative-http-v1",
    componentId: "identity-chain",
    findings: ["identity-chain"],
    routes: [
      {
        method: "GET",
        path: "/scenario",
        response: { status: 200, contentType: "text/plain; charset=utf-8", inlineBody: "bounded scenario\n" },
      },
      {
        method: "GET",
        path: "/evidence",
        response: { status: 200, contentType: "application/json; charset=utf-8", artifactPath: "evidence.json" },
      },
    ],
  };
}

test("serves the fixed ABI and declarative routes without executing package code", async () => {
  const roots = await fixture(validManifest(), '{"event":"approved"}\n');
  const catalog = await loadComponentCatalog(roots);
  const server = createTargetServer(catalog);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);
    assert.equal(await health.text(), "ready\n");
    const version = await (await fetch(`${base}/version`)).json();
    assert.equal(version.runtimeAbi, "http-v1");
    assert.deepEqual(version.findings, ["identity-chain"]);
    assert.equal(await (await fetch(`${base}/scenario`)).text(), "bounded scenario\n");
    assert.equal(await (await fetch(`${base}/evidence`)).text(), '{"event":"approved"}\n');
    assert.equal((await fetch(`${base}/scenario`, { method: "POST" })).status, 404);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("executes only a digest-bound signed component adapter through the fixed worker ABI", async () => {
  const handler = `export async function handle(request, context) {
    const parsed = JSON.parse(request.body || "{}");
    return { status: parsed.user === "legacy" ? 200 : 401, contentType: "application/json; charset=utf-8", body: { operation: context.operation, accepted: parsed.user === "legacy" } };
  }\n`;
  const manifest = validManifest();
  manifest.kind = "signed-node-handler-v1";
  manifest.handler = { path: "handler.mjs", sha256: createHash("sha256").update(handler).digest("hex") };
  manifest.routes = [{ method: "POST", path: "/login", operation: "legacy-login" }];
  const roots = await fixture(manifest);
  await writeFile(join(roots.packageRoot, "identity-chain", "handler.mjs"), handler);
  const catalog = await loadComponentCatalog(roots);
  const server = createTargetServer(catalog);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user: "legacy" }),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { operation: "legacy-login", accepted: true });
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("rejects a component adapter whose bytes do not match its signed manifest", async () => {
  const manifest = validManifest();
  manifest.kind = "signed-node-handler-v1";
  manifest.handler = { path: "handler.mjs", sha256: "a".repeat(64) };
  manifest.routes = [{ method: "POST", path: "/login", operation: "legacy-login" }];
  const roots = await fixture(manifest);
  await writeFile(join(roots.packageRoot, "identity-chain", "handler.mjs"), "export function handle() {}\n");
  await assert.rejects(loadComponentCatalog(roots), /handler digest does not match/);
});

test("rejects a component whose manifest kind differs from the builder policy", async () => {
  const roots = await fixture(validManifest());
  await writeFile(roots.policyPath, JSON.stringify({
    schemaVersion: "codegate-component-policy/v1",
    components: [{ componentId: "identity-chain", runtimeKind: "signed-node-handler-v1" }],
  }));
  await assert.rejects(loadComponentCatalog(roots), /kind does not match the signed build policy/);
});

test("rejects command fields and reserved route overrides", async () => {
  const commandManifest = validManifest();
  commandManifest.command = ["sh", "-c", "id"];
  const roots = await fixture(commandManifest);
  await assert.rejects(loadComponentCatalog(roots), /unsupported fields: command/);

  const reservedManifest = validManifest();
  reservedManifest.routes[0].path = "/health";
  const reservedRoots = await fixture(reservedManifest);
  await assert.rejects(loadComponentCatalog(reservedRoots), /invalid or reserved/);
});

test("rejects an artifact symlink that leaves the approved artifact root", async (context) => {
  const manifest = validManifest();
  manifest.routes = [{
    method: "GET",
    path: "/leak",
    response: { status: 200, contentType: "text/plain; charset=utf-8", artifactPath: "outside.txt" },
  }];
  const roots = await fixture(manifest);
  const outside = join(roots.artifactRoot, "..", "outside.txt");
  await writeFile(outside, "must-not-load");
  try {
    await symlink(outside, join(roots.artifactRoot, "outside.txt"));
  } catch (error) {
    if (process.platform === "win32" && error && typeof error === "object" && ["EPERM", "EACCES"].includes(error.code)) {
      context.skip("Windows developer mode is required for symlink creation");
      return;
    }
    throw error;
  }
  await assert.rejects(loadComponentCatalog(roots), /must not escape/);
});
