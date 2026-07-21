import { resolve } from "node:path";

import {
  createDatabase,
  SqliteDevelopmentRepository,
} from "../src/database.ts";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const databasePath = resolve(
  process.argv[2] ??
    process.env.CODEGATE_DB_PATH ??
    resolve(repositoryRoot, "scripts/.runtime/codegate.db"),
);

const database = createDatabase(databasePath);
try {
  const repository = new SqliteDevelopmentRepository(database);
  repository.initialize();
  repository.seedDevelopmentCapabilityData();

  const counts = database
    .prepare(
      `SELECT
        (SELECT count(*) FROM organizations) AS organizations,
        (SELECT count(*) FROM users) AS users,
        (SELECT count(*) FROM organization_memberships) AS memberships,
        (SELECT count(*)
           FROM users u
           LEFT JOIN organization_memberships m ON m.user_id = u.id
          WHERE m.user_id IS NULL) AS personal_users,
        (SELECT count(*) FROM labs
          WHERE json_extract(config_json, '$.fixture') = 1) AS capability_labs,
        (SELECT count(*) FROM challenge_results
          WHERE json_extract(evidence_json, '$.verified') = 1) AS verified_results`,
    )
    .get();
  const duplicateMemberships = database
    .prepare(
      `SELECT user_id
         FROM organization_memberships
        GROUP BY user_id
       HAVING count(*) > 1`,
    )
    .all();

  console.log(
    JSON.stringify({ databasePath, counts, duplicateMemberships }, null, 2),
  );
} finally {
  database.close();
}
