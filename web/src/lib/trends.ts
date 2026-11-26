import { SEVERITIES, type Severity } from './ui/format';

/** One row of `GET /api/v1/trends` or `/api/v1/services/{id}/trend`. */
export type TrendRow = { day: string; realm?: string } & Record<Severity, number>;
/** One calendar day; a severity is `null` when no snapshot was taken that day. */
export type TrendDay = { day: string } & Record<Severity, number | null>;

/** The `days` UTC days ending at `today` (or at the newest row, when the
 * browser's clock is behind the server's), oldest first, with each severity
 * summed over the rows (realms) of that day. Days without a row stay null, so
 * a chart shows a gap instead of a false zero. */
export function dailySeries(rows: TrendRow[], days: number, today: Date = new Date()): TrendDay[] {
  const newest = rows.reduce((max, r) => Math.max(max, Date.parse(r.day + 'T00:00:00Z')), -Infinity);
  const end = Math.max(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()), newest);
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

/** A chart point; `value` is null on a day without a snapshot. */
export type Point = { day: string; value: number | null };
/** How to draw `points`: `runs` are the index ranges to join with a line
 * (a missing day breaks it), `lone` the days with no neighbour on either side
 * (drawn as a dot), `last` the index of the newest recorded day or -1. */
export function lineShape(points: Point[]): { runs: number[][]; lone: number[]; last: number } {
  const runs: number[][] = [];
  points.forEach((p, i) => {
    if (p.value === null) return;
    if (i > 0 && points[i - 1]!.value !== null) runs[runs.length - 1]!.push(i); else runs.push([i]);
  });
  return { runs: runs.filter(r => r.length > 1), lone: runs.filter(r => r.length === 1).map(r => r[0]!), last: runs.at(-1)?.at(-1) ?? -1 };
}
