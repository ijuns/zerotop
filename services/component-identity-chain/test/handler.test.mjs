import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { handle } from "../handler.mjs";

test("manifest pins the exact approved handler bytes", async () => {
  const handlerBytes = await readFile(new URL("../handler.mjs", import.meta.url));
  const manifest = JSON.parse(await readFile(new URL("../component.json", import.meta.url), "utf8"));
  assert.equal(createHash("sha256").update(handlerBytes).digest("hex"), manifest.handler.sha256);
  assert.equal(manifest.kind, "signed-node-handler-v1");
});

test("exposes the bounded IDOR finding over the fixed component ABI", async () => {
  const result = await handle(
    { method: "GET", path: "/api/accounts", query: { accountId: "1002" }, headers: {}, body: "" },
    { componentId: "identity-chain", operation: "read-account" },
  );
  assert.equal(result.status, 200);
  assert.equal(result.body.account.owner, "analyst-b");
  assert.equal(result.body.finding, "scenario-idor");
});

test("never reaches host data or arbitrary files", async () => {
  const result = await handle(
    { method: "GET", path: "/api/accounts", query: { accountId: "../../etc/passwd" }, headers: {}, body: "" },
    { componentId: "identity-chain", operation: "read-account" },
  );
  assert.deepEqual(result, {
    status: 404,
    contentType: "application/json; charset=utf-8",
    body: { error: "account_not_found" },
  });
});
