import { describe, expect, it } from 'vitest';
import { riskScore, severities, statusUrl } from './overview';
describe('overview', () => {
  it('weights critical, high and medium findings', () => { expect(riskScore(2, 3, 4)).toBe(33); });
  it('orders severity consistently', () => { expect(severities).toEqual(['critical', 'high', 'medium', 'low', 'unknown']); });
  it('encodes selected realms in the status request', () => { expect(statusUrl([])).toBe('/api/v1/status'); expect(statusUrl(['a b', 'prod'])).toBe('/api/v1/status?realms=a+b%2Cprod'); });
});
