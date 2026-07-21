import assert from "node:assert/strict";
import test from "node:test";
import { backendPath, desktopHost, parseAuthorizedRun, parseTicketExchange, runIdFromPath } from "../src/routing.ts";

test("accepts only bounded run session paths", () => {
  assert.equal(runIdFromPath("/sessions/run_123/desktop/vnc.html"), "run_123");
  assert.equal(runIdFromPath("/sessions/..%2Fadmin/desktop"), null);
  assert.equal(runIdFromPath("/other/run_123"), null);
});

test("parses a one-time ticket exchange response", () => {
  const result = parseTicketExchange(
    {
      data: {
        access: {
          runId: "run_123",
          namespace: "range-run-123",
          expiresAt: "2026-07-21T15:00:00.000Z",
        },
      },
    },
    "run_123",
  );
  assert.equal(result.namespace, "range-run-123");
  assert.throws(
    () =>
      parseTicketExchange(
        {
          data: {
            access: {
              runId: "other",
              namespace: "range-run-other",
              expiresAt: "2026-07-21T15:00:00.000Z",
            },
          },
        },
        "run_123",
      ),
    /does not match/,
  );
});

test("builds only run-scoped service DNS names and backend paths", () => {
  assert.equal(desktopHost("range-run-123"), "desktop.range-run-123.svc.cluster.local");
  assert.throws(() => desktopHost("kube-system"), /invalid namespace/);
  assert.equal(
    backendPath("/sessions/run_123/desktop/websockify", "?token=not-forwarded", "run_123"),
    "/websockify?token=not-forwarded",
  );
});

test("requires API authorization response to match the run and active namespace", () => {
  const run = parseAuthorizedRun(
    {
      data: {
        run: {
          id: "run_123",
          status: "ready",
          metadata: { namespace: "range-run-123" },
        },
      },
    },
    "run_123",
  );
  assert.equal(run.namespace, "range-run-123");
  assert.throws(
    () =>
      parseAuthorizedRun(
        { data: { run: { id: "run_other", status: "ready", metadata: { namespace: "range-run-other" } } } },
        "run_123",
      ),
    /does not match/,
  );
});
