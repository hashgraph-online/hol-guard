/**
 * Orders listing requests so only the newest one applies its listing. A
 * request a newer one superseded reports that newer one's outcome once it
 * settles, so a caller that waits for "the listing now shows my change" never
 * hears yes while the listing on screen is still the older one.
 */
export function createListingSequence() {
  let generation = 0;
  let latest: Promise<boolean> = Promise.resolve(true);
  return {
    /**
     * Starts a request. `applied` says whether its result put a listing on
     * screen; `listed` resolves once the newest request has settled, with
     * whether that one did.
     */
    start<T>(
      request: (isCurrent: () => boolean) => Promise<T>,
      applied: (result: T) => boolean,
    ): { result: Promise<T>; isCurrent: () => boolean; listed: Promise<boolean> } {
      generation += 1;
      const mine = generation;
      const isCurrent = () => generation === mine;
      const result = request(isCurrent);
      const listed = result.then((value) => (isCurrent() ? applied(value) : latest));
      latest = listed;
      return { result, isCurrent, listed };
    },
  };
}
