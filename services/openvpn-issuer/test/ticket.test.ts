import assert from "node:assert/strict";
import test from "node:test";

import { ServiceError } from "../src/errors.ts";
import { PlatformApiTicketExchanger } from "../src/ticket.ts";

test("download exchanger authenticates to the API and validates run/profile binding", async () => {
  let body: unknown;
  const exchanger = new PlatformApiTicketExchanger({
    apiUrl: "http://codegate-api:8080/",
    internalToken: "download-internal-token-123456",
    fetchImpl: async (request, init) => {
      assert.equal(
        String(request),
        "http://codegate-api:8080/v1/internal/openvpn-tickets/exchange",
      );
      assert.equal(
        new Headers(init?.headers).get("authorization"),
        "Bearer download-internal-token-123456",
      );
      body = JSON.parse(String(init?.body));
      return Response.json({
        data: {
          access: {
            runId: "run-1",
            openVpn: { profileId: "vpn-profile-1" },
          },
        },
      });
    },
  });
  assert.deepEqual(await exchanger.exchange("ticket-value"), {
    runId: "run-1",
    profileId: "vpn-profile-1",
  });
  assert.deepEqual(body, { ticket: "ticket-value" });
});

test("download exchanger rejects malformed API access metadata", async () => {
  const exchanger = new PlatformApiTicketExchanger({
    apiUrl: "http://codegate-api:8080",
    internalToken: "download-internal-token-123456",
    fetchImpl: async () => Response.json({ data: { access: { runId: "run-1" } } }),
  });
  await assert.rejects(
    exchanger.exchange("ticket-value"),
    (error: unknown) =>
      error instanceof ServiceError && error.code === "invalid_ticket_exchange",
  );
});
