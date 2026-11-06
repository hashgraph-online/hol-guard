import { useEffect, useState } from "react";

import { createCommandActivityClient } from "../command-activity/command-activity-api";
import { DEFAULT_COMMAND_ACTIVITY_FILTERS } from "../command-activity/command-activity-state";
import type { CommandActivityItem } from "../command-activity/command-activity-types";
import { fetchCommandActivityApi } from "../guard-api";

const client = createCommandActivityClient(fetchCommandActivityApi);

export function useProtectionModuleActivity(extensionId: string) {
  const [items, setItems] = useState<CommandActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setItems([]);
    setLoading(true);
    setUnavailable(false);
    void client.fetchPage(
      { ...DEFAULT_COMMAND_ACTIVITY_FILTERS, extension_id: extensionId, limit: 8 },
      null,
      controller.signal,
    ).then(
      (page) => {
        if (controller.signal.aborted) return;
        setItems(page.items);
        setLoading(false);
      },
      () => {
        if (controller.signal.aborted) return;
        setItems([]);
        setLoading(false);
        setUnavailable(true);
      },
    );
    return () => controller.abort();
  }, [extensionId]);

  return { items, loading, unavailable };
}
