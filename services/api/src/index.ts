import { createApplication } from "./app.ts";
import { seedDemoData } from "./demo-seed.ts";

const port = Number.parseInt(process.env.PORT ?? "8080", 10);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}

const application = createApplication();
await application.ready;

if (process.env.DEMO_SEED === "true") {
  try {
    await seedDemoData(application.repository);
    console.log(JSON.stringify({ level: "info", message: "Demo data seeded" }));
  } catch (error) {
    // A failed demo seed must not prevent the service from starting.
    console.error(
      JSON.stringify({ level: "error", message: "Demo seed failed", error: String(error) }),
    );
  }
}
application.server.listen(port, "0.0.0.0", () => {
  console.log(
    JSON.stringify({
      level: "info",
      message: "CODEGATE Range API listening",
      port,
      authMode: application.authMode,
      repositoryMode: application.repositoryMode,
    }),
  );
});

let stopping = false;
async function shutdown(signal: string): Promise<void> {
  if (stopping) return;
  stopping = true;
  console.log(JSON.stringify({ level: "info", message: "Shutting down", signal }));
  await application.close();
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));
