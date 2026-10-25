const COUNT_FORMAT = new Intl.NumberFormat("en-US");

/** Counts on the About page read with grouping, e.g. 1,284 receipts. */
export function formatAboutCount(value: number): string {
  return COUNT_FORMAT.format(value);
}
