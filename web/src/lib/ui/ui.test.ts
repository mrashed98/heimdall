import { describe, expect, it } from 'vitest';
import { epssTone, epssWidth, severityTone } from './format';

describe('format helpers', () => {
  it('normalises severities', () => {
    expect(severityTone('CRITICAL')).toBe('critical');
    expect(severityTone('High')).toBe('high');
    expect(severityTone('weird')).toBe('unknown');
  });
  it('sizes the EPSS bar', () => {
    expect(epssWidth(0.944)).toBe('94.4%');
    expect(epssWidth(null)).toBe('0%');
    expect(epssWidth(undefined)).toBe('0%');
  });
  it('colours the EPSS bar by likelihood', () => {
    expect(epssTone(0.5)).toBe('critical');
    expect(epssTone(0.05)).toBe('high');
    expect(epssTone(0.001)).toBe('low');
    expect(epssTone(null)).toBe('unknown');
  });
});

// Pages and components style themselves only through tokens.css.
const sources = import.meta.glob('../../**/*.svelte', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
describe('design system', () => {
  it('scans every component', () => { expect(Object.keys(sources).length).toBeGreaterThan(20); });
  it('has no raw hex colours outside tokens and the logo', () => {
    const offenders = Object.entries(sources)
      .filter(([path]) => path !== './Logo.svelte')
      .filter(([, text]) => /#[0-9a-f]{3,8}\b/i.test(text))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });
});

const tokens = Object.values(import.meta.glob('./tokens.css', { query: '?raw', import: 'default', eager: true }))[0] as string;
describe('tokens', () => {
  it('defines every custom property the components use', () => {
    const defined = new Set([...tokens.matchAll(/(--[a-z0-9-]+)\s*:/g)].map(m => m[1]));
    const used = new Set(Object.values(sources).flatMap(text => [...text.matchAll(/var\((--[a-z0-9-]+)/g)].map(m => m[1]!)));
    expect([...used].filter(name => !defined.has(name))).toEqual([]);
  });
});
