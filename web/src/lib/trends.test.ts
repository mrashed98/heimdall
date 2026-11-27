import { describe, expect, it } from 'vitest';
import { dailySeries, lineShape, niceMax } from './trends';
const zero = { medium: 0, low: 0, unknown: 0 };
describe('trend series', () => {
  it('sums realms per day and leaves days without a snapshot empty', () => {
    const rows = [
      { day: '2026-11-24', realm: 'prod', critical: 2, high: 5, ...zero },
      { day: '2026-11-24', realm: 'dev', critical: 1, high: 0, ...zero },
      { day: '2026-11-26', realm: 'prod', critical: 0, high: 4, ...zero },
      { day: '2026-10-01', realm: 'prod', critical: 9, high: 9, ...zero },
    ];
    const series = dailySeries(rows, 3, new Date('2026-11-26T23:30:00Z'));
    expect(series.map(d => [d.day, d.critical, d.high])).toEqual([
      ['2026-11-24', 3, 5], ['2026-11-25', null, null], ['2026-11-26', 0, 4],
    ]);
  });
  it('breaks the line at missing days and dots a day with no neighbours', () => {
    const v = (...xs: (number | null)[]) => xs.map((value, i) => ({ day: String(i), value }));
    expect(lineShape(v(1, 2, null, 3, null, 4, 5, null))).toEqual({ runs: [[0, 1], [5, 6]], lone: [3], last: 6 });
    expect(lineShape(v(null, null))).toEqual({ runs: [], lone: [], last: -1 });
    expect(lineShape(v(0))).toEqual({ runs: [], lone: [0], last: 0 });
  });
  it('ends on the newest row when the browser clock is behind the server', () => {
    const rows = [{ day: '2026-11-27', realm: 'prod', critical: 4, high: 0, ...zero }];
    const series = dailySeries(rows, 2, new Date('2026-11-26T23:59:00Z'));
    expect(series.map(d => [d.day, d.critical])).toEqual([['2026-11-26', null], ['2026-11-27', 4]]);
  });
  it('rounds the axis up to 1, 2 or 5 times a power of ten', () => {
    expect([0, 1, 3, 7, 12, 180, 501].map(niceMax)).toEqual([1, 1, 5, 10, 20, 200, 1000]);
  });
});
