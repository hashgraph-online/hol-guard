export interface PaginationState {
  page: number;
  pageSize: number;
  total: number;
}

export function paginate<T>(items: T[], page: number, pageSize: number): T[] {
  const start = page * pageSize;
  return items.slice(0, start + pageSize);
}

export function totalPages(total: number, pageSize: number): number {
  if (pageSize <= 0) return 0;
  return Math.ceil(total / pageSize);
}

export function hasMore(page: number, pageSize: number, total: number): boolean {
  return (page + 1) * pageSize < total;
}
