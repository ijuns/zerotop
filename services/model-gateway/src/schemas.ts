type Schema = Record<string, unknown>;

const identifier: Schema = { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" };
const shortText: Schema = { type: "string", minLength: 1, maxLength: 2_000 };
const sha256: Schema = { type: "string", pattern: "^[a-f0-9]{64}$" };
const cve: Schema = { type: "string", pattern: "^CVE-[0-9]{4}-[0-9]{4,7}$" };
const technique: Schema = { type: "string", pattern: "^T[0-9]{4}(?:\\.[0-9]{3})?$" };

export function generationPlanSchema(questionTypes: string[], team: "blue" | "red", rubricIds: string[]): Schema {
  const option = object({ id: identifier, label: { type: "string", minLength: 1, maxLength: 500 } });
  const question = object({
    id: identifier,
    type: { type: "string", enum: questionTypes },
    prompt: { type: "string", minLength: 10, maxLength: 2_000 },
    points: { type: "integer", minimum: 1, maximum: 1_000 },
    options: nullable({ type: "array", minItems: 2, maxItems: 8, items: option }),
    answer: object({
      optionIds: nullable({ type: "array", minItems: 1, maxItems: 8, items: identifier }),
      techniqueIds: nullable({ type: "array", minItems: 1, maxItems: 20, items: technique }),
      expectedEvidenceIds: nullable({ type: "array", minItems: 1, maxItems: 100, items: identifier }),
      rubricId: nullable(rubricIds.length > 0 ? { type: "string", enum: rubricIds } : identifier),
    }),
  });
  const httpProbe = {
    id: identifier,
    method: { type: "string", enum: ["GET", "HEAD"] },
    path: { type: "string", pattern: "^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$" },
    expectedStatuses: { type: "array", minItems: 1, maxItems: 8, items: { type: "integer", minimum: 100, maximum: 599 } },
    bodyIncludes: { type: "array", minItems: 0, maxItems: 8, items: { type: "string", minLength: 1, maxLength: 200 } },
  };
  return object({
    scenario: object({
      summary: { type: "string", minLength: 20, maxLength: 2_000 },
      logSources: { type: "array", minItems: team === "blue" ? 4 : 1, maxItems: 20, items: identifier },
      attackChain: { type: "array", minItems: 1, maxItems: 30, items: object({ id: technique, name: shortText, tactic: identifier }) },
    }),
    learning: object({
      summary: { type: "string", minLength: 20, maxLength: 2_000 },
      prerequisites: { type: "array", minItems: 1, maxItems: 20, items: { type: "string", minLength: 1, maxLength: 500 } },
      objectives: { type: "array", minItems: 1, maxItems: 20, items: { type: "string", minLength: 1, maxLength: 500 } },
      sections: { type: "array", minItems: 2, maxItems: 12, items: object({ id: identifier, title: { type: "string", minLength: 3, maxLength: 120 }, bodyMarkdown: { type: "string", minLength: 20, maxLength: 20_000 } }) },
    }),
    questions: { type: "array", minItems: questionTypes.length, maxItems: questionTypes.length, items: question },
    target: object({
      name: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$" },
      packages: { type: "array", minItems: 0, maxItems: 20, items: object({ name: identifier, version: { type: "string", minLength: 1, maxLength: 100 } }) },
      artifacts: { type: "array", minItems: 0, maxItems: 20, items: object({ sha256, url: { type: "string", minLength: 12, maxLength: 2_000 }, destination: { type: "string", pattern: "^/opt/codegate/artifacts/[A-Za-z0-9._-]{1,128}$" } }) },
      functionalProbes: { type: "array", minItems: 1, maxItems: 20, items: object(httpProbe) },
      vulnerabilityProbes: { type: "array", minItems: 1, maxItems: 20, items: object({ ...httpProbe, cveId: nullable(cve), findingId: nullable(identifier) }) },
    }),
    telemetryEvents: {
      type: "array",
      minItems: team === "blue" ? 1 : 0,
      maxItems: team === "blue" ? 100 : 0,
      items: object({
        id: identifier,
        message: { type: "string", minLength: 1, maxLength: 2_000 },
        dataset: identifier,
        category: identifier,
        sourceIp: { type: "string", minLength: 3, maxLength: 45 },
        techniqueIds: { type: "array", minItems: 1, maxItems: 20, items: technique },
      }),
    },
  });
}

export const reviewSchema: Schema = object({
  passed: { type: "boolean" },
  confidence: { type: "number", minimum: 0, maximum: 1 },
  riskScore: { type: "number", minimum: 0, maximum: 1 },
});

export function rubricSchema(criterionIds: string[]): Schema {
  return object({
    criterionScores: {
      type: "array",
      minItems: criterionIds.length,
      maxItems: criterionIds.length,
      items: object({ criterionId: { type: "string", enum: criterionIds }, score: { type: "number", minimum: 0, maximum: 1 } }),
    },
  });
}

function object(properties: Record<string, Schema>): Schema {
  return { type: "object", properties, required: Object.keys(properties), additionalProperties: false };
}

function nullable(schema: Schema): Schema {
  return { anyOf: [schema, { type: "null" }] };
}
