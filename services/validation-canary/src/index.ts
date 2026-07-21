import { createValidationCanaryServer } from "./server.ts";

const port = Number(process.env.PORT ?? "8080");
if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  throw new Error("PORT must be an integer between 1 and 65535");
}

const server = createValidationCanaryServer();
server.listen(port, "0.0.0.0", () => {
  console.log(`CODEGATE validation canary listening on :${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => server.close(() => process.exit(0)));
}
