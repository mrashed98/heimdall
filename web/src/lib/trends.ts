import { SEVERITIES, type Severity } from './ui/format';

/** One row of `GET /api/v1/trends` or `/api/v1/services/{id}/trend`. */
export type TrendRow = { day: string; realm?: string } & Record<Severity, number>;
/** One calendar day; a severity is `null` when no snapshot was taken that day. */
export type TrendDay = { day: string } & Record<Severity, number | null>;

/** The `days` UTC days ending at `today`, oldest first, with each severity
 * summed over the rows (realms) of that day. Days without a row stay null, so
 * a chart shows a gap instead of a false zero. */
export function dailySeries(rows: TrendRow[], days: number, today: Date = new Date()): TrendDay[] {
  const end = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
  const byDay = new Map<string, TrendDay>();
  const out: TrendDay[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const day = new Date(end - i * 86_400_000).toISOString().slice(0, 10);
    const entry = { day, ...Object.fromEntries(SEVERITIES.map(s => [s, null])) } as TrendDay;
    byDay.set(day, entry); out.push(entry);
  }
  for (const row of rows) {
    const entry = byDay.get(row.day);
    if (entry) for (const s of SEVERITIES) entry[s] = (entry[s] ?? 0) + row[s];
  }
  return out;
}

/** A clean axis maximum at or above `value`: 1, 2 or 5 times a power of ten. */
export function niceMax(value: number): number {
  if (value <= 0) return 1;
  const power = 10 ** Math.floor(Math.log10(value));
  return [1, 2, 5, 10].map(m => m * power).find(m => m >= value)!;
}
