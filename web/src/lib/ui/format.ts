/** Every severity, worst first. The one list: the rest of the app imports it. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
export type Severity = typeof SEVERITIES[number];
export type Tone = Severity;
/** Any severity string to one of the five design-system tones. */
export function severityTone(severity: string | null | undefined): Tone {
  const s = (severity ?? '').toLowerCase() as Tone;
  return SEVERITIES.includes(s) ? s : 'unknown';
}
/** EPSS score (0 to 1) as a CSS width. */
export function epssWidth(score: number | null | undefined): string {
  return score == null ? '0%' : `${Math.round(Math.min(1, Math.max(0, score)) * 1000) / 10}%`;
}
/** Bar colour: 10%+ likely exploited, 1%+ worth a look. */
export function epssTone(score: number | null | undefined): Tone {
  if (score == null) return 'unknown';
  return score >= 0.1 ? 'critical' : score >= 0.01 ? 'high' : 'low';
}
/** How long before `now` an ISO time was: "just now", "5m ago", "2h ago", "3d ago". */
export function relativeTime(iso: string, now: Date): string {
  const ms = now.getTime() - Date.parse(iso);
  if (Number.isNaN(ms)) return '';
  const m = Math.floor(ms / 60_000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`;
}
