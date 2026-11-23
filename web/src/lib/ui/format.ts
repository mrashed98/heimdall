export type Tone = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
const tones: Tone[] = ['critical', 'high', 'medium', 'low'];
/** Any severity string to one of the five design-system tones. */
export function severityTone(severity: string | null | undefined): Tone {
  const s = (severity ?? '').toLowerCase() as Tone;
  return tones.includes(s) ? s : 'unknown';
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
