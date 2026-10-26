import { useEffect, useState } from "react";
import { createCommandActivityClient } from "../command-activity/command-activity-api";
import { fetchCommandActivityApi } from "../guard-api";
import {
  SPOTLIGHT_ACTIVITY_DAYS,
  spotlightActivityFromDimensions,
  type SpotlightActivityCount,
} from "./extensions-spotlight-model";

/**
 * How much work each extension actually did on this device.
 *
 * The only honest popularity signal Guard has locally: counts of commands it
 * checked here, from the same analytics the Activity screen shows. Nothing
 * leaves the device and nothing is estimated. A device with no history, or a
 * daemon that cannot answer, simply yields no counts, and the spotlight falls
 * back to its declared starter set rather than inventing a ranking.
 */

const TOP_LIMIT = 12;

export interface ExtensionPopularity {
  counts: SpotlightActivityCount[];
  settled: boolean;
}

export function useExtensionPopularity(active: boolean): ExtensionPopularity {
  const [state, setState] = useState<ExtensionPopularity>({ counts: [], settled: false });

  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    const client = createCommandActivityClient(fetchCommandActivityApi);
    void client
      .fetchAnalytics(
        { days: SPOTLIGHT_ACTIVITY_DAYS, top_limit: TOP_LIMIT, dimension: null, dimension_value: null },
        controller.signal,
      )
      .then((analytics) => {
        if (controller.signal.aborted) return;
        setState({ counts: spotlightActivityFromDimensions(analytics.dimensions.extension), settled: true });
      })
      .catch(() => {
        // Popularity is decoration on a security surface: a failure here must
        // never surface an error, only drop this tier of the fallback.
        if (!controller.signal.aborted) setState({ counts: [], settled: true });
      });
    return () => controller.abort();
  }, [active]);

  return state;
}
