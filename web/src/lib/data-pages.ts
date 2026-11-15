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
