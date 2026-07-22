import { LAB_DIR, composeCommand, requireSuccess, type CommandRunner } from "./lab-process";

const SENTINEL = "guard-private-command-sentinel";
const PROBE = `
import json
import re
import sqlite3
sentinel = ${JSON.stringify(SENTINEL)}
with sqlite3.connect("/guard-home/guard.db") as connection:
    tables = [
        str(row[0])
        for row in connection.execute("select name from sqlite_master where type = 'table'")
        if re.fullmatch(r"command_activity(?:_[a-z0-9_]+)?", str(row[0]))
    ]
    activity_rows = [row for table in tables for row in connection.execute(f'select * from "{table}"')]
    redacted_receipts = [
        row[0]
        for row in connection.execute("select envelope_redacted_json from runtime_receipt_envelopes")
    ]
print(json.dumps({
    "activity": "clean" if sentinel not in json.dumps(activity_rows, default=str) else "exposed",
    "redacted_receipts": "clean" if sentinel not in json.dumps(redacted_receipts) else "exposed",
    "schema": "clean" if "command_activity" in tables else "missing",
}, sort_keys=True))
`;

export async function verifyDatabasePrivacy(
  project: string,
  environment: Record<string, string>,
  runner: CommandRunner,
): Promise<void> {
  const result = requireSuccess(
    await runner(composeCommand(project, "exec", "-T", "guard", "python", "-c", PROBE), {
      cwd: LAB_DIR,
      env: environment,
    }),
    "database privacy probe",
  );
  if (result !== '{"activity": "clean", "redacted_receipts": "clean", "schema": "clean"}') {
    throw new Error("private command value escaped its local persistence boundary");
  }
}
