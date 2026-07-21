const ACCOUNTS = Object.freeze({
  "1001": Object.freeze({ id: "1001", owner: "analyst-a", role: "viewer", apiKeyHint: "cg_demo_a" }),
  "1002": Object.freeze({ id: "1002", owner: "analyst-b", role: "admin", apiKeyHint: "cg_demo_b" }),
});

export async function handle(request, context) {
  if (context.operation !== "read-account") return response(404, { error: "operation_not_found" });
  const accountId = String(request.query?.accountId ?? "");
  const account = ACCOUNTS[accountId];
  if (!account) return response(404, { error: "account_not_found" });

  // Intentional training weakness: ownership is not checked. The component is
  // runnable only inside the isolated range and exposes synthetic records.
  return response(200, { account, finding: "scenario-idor" });
}

function response(status, body) {
  return { status, contentType: "application/json; charset=utf-8", body };
}
