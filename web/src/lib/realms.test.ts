import { expect, it } from 'vitest';
import { realmUrl, selectedRealms } from './realms';
it('round-trips realm selections while preserving other URL state', () => {
  const result = realmUrl('https://example.test/findings?sort=severity#top', ['one', 'two']);
  expect(result).toBe('/findings?sort=severity&realms=one%2Ctwo#top');
  expect(selectedRealms(new URL(result, 'https://example.test').search)).toEqual(['one', 'two']);
  expect(realmUrl('https://example.test' + result, [])).toBe('/findings?sort=severity#top');
});
