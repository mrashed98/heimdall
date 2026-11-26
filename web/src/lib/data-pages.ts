export const PAGE_SIZE = 25;
export function dataUrl(path: string, realms: string[], offset: number, sort: string, order: string, extra: Record<string, string> = {}): string {
  const q = new URLSearchParams({limit: String(PAGE_SIZE), offset: String(offset), sort, order});
  if (realms.length) q.set('realms', realms.join(','));
  for (const [key, value] of Object.entries(extra)) if (value) q.set(key, value);
  return `${path}?${q}`;
}
export function nextSort(current: string, order: string, field: string): [string, string] {
  return [field, current === field && order === 'asc' ? 'desc' : 'asc'];
}
export function expiryError(date: string): string {
  return !date || date <= new Date().toISOString().slice(0, 10) ? 'Choose a date after today (UTC).' : '';
}
/** Where a component runs: package URL text, optionally only versions below `below`. */
export function componentUrl(search: string, below: string, realms: string[], offset: number): string {
  const q = new URLSearchParams({search: search.trim(), limit: String(PAGE_SIZE), offset: String(offset)});
  if (below.trim()) q.set('version_lt', below.trim());
  if (realms.length) q.set('realms', realms.join(','));
  return `/api/v1/components?${q}`;
}
