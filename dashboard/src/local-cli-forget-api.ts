import { fetchLocalCliApi } from "./guard-api";
import { readJson, type LocalCliItem } from "./local-cli-api";

export async function forgetLocalCli(item: Pick<LocalCliItem, "cli_id" | "identity_hash">): Promise<void> {
  await readJson(await fetchLocalCliApi("/v1/local-clis/forget", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cli_id: item.cli_id, identity_hash: item.identity_hash }),
  }));
}
