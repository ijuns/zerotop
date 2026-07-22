import { mkdir, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { expandBlueTelemetryEvents } from "./blue-telemetry.ts";

const outputPath = process.env.SCENARIO_LOG_PATH ?? "/var/log/zerotop/scenario.ndjson";
const encodedEvents = process.env.SCENARIO_EVENTS_BASE64 ?? "";
const encodedGeneration = process.env.SCENARIO_GENERATION_BASE64 ?? "";

const events = parseEvents(encodedEvents);
const generation = parseGeneration(encodedGeneration);
await mkdir(dirname(outputPath), { recursive: true });

const documents = expandBlueTelemetryEvents(events, generation);
const temporaryPath = `${outputPath}.tmp`;
await writeFile(temporaryPath, `${documents.map((item) => JSON.stringify(item.document)).join("\n")}\n`, {
  encoding: "utf8",
  mode: 0o640,
});
await rename(temporaryPath, outputPath);

console.log(JSON.stringify({
  level: "info",
  service: "scenario-log-generator",
  eventCount: documents.length,
  profile: generation.profile,
  timeRangeMinutes: generation.timeRangeMinutes,
  outputPath,
}));

// The runtime owns this container for the life of the lab. Keeping the process
// alive makes health and lifecycle state explicit without generating duplicate
// evidence events.
setInterval(() => undefined, 60_000);

function parseEvents(value) {
  if (!value || value.length > 1_000_000) {
    throw new Error("SCENARIO_EVENTS_BASE64 is missing or too large");
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(value, "base64").toString("utf8"));
  } catch (error) {
    throw new Error("SCENARIO_EVENTS_BASE64 is not valid base64 JSON", { cause: error });
  }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 100) {
    throw new Error("Scenario events must contain 1-100 entries");
  }
  return parsed.map((item, index) => {
    if (!isRecord(item) || typeof item.id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(item.id)) {
      throw new Error(`Scenario event ${index} has an invalid id`);
    }
    if (!isRecord(item.document)) throw new Error(`Scenario event ${index} has no document`);
    return { id: item.id, document: item.document };
  });
}

function parseGeneration(value) {
  if (!value) {
    return {
      schemaVersion: 1,
      profile: "generic_endpoint_activity",
      totalEvents: 1_200,
      timeRangeMinutes: 60,
      seed: "zerotop-default-telemetry",
      timelineAnchor: new Date().toISOString(),
    };
  }
  if (value.length > 64_000) throw new Error("SCENARIO_GENERATION_BASE64 is too large");
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(value, "base64").toString("utf8"));
  } catch (error) {
    throw new Error("SCENARIO_GENERATION_BASE64 is not valid base64 JSON", { cause: error });
  }
  if (!isRecord(parsed)) throw new Error("Scenario generation configuration must be an object");
  return parsed;
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
