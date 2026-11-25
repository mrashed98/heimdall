import { describe, expect, it } from 'vitest';
import { createRawSnippet } from 'svelte';
import { render } from 'svelte/server';
import Dialog from './Dialog.svelte';
import { epssTone, epssWidth, relativeTime, severityTone } from './format';

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
  it('says how long ago a time was', () => {
    const now = new Date('2026-11-24T12:00:00Z');
    expect(relativeTime('2026-11-24T11:59:30Z', now)).toBe('just now');
    expect(relativeTime('2026-11-24T12:00:10Z', now)).toBe('just now');
    expect(relativeTime('2026-11-24T11:55:00Z', now)).toBe('5m ago');
    expect(relativeTime('2026-11-24T10:00:00Z', now)).toBe('2h ago');
    expect(relativeTime('2026-11-21T12:00:00Z', now)).toBe('3d ago');
    expect(relativeTime('not a date', now)).toBe('');
  });
});

describe('Dialog', () => {
  const text = (s: string) => createRawSnippet(() => ({ render: () => `<p>${s}</p>` }));
  it('renders title and is labelled by it', () => {
    const { body } = render(Dialog, { props: { open: false, title: 'Add channel', children: text('Form'), actions: text('Save') } });
    const dialog = body.match(/<dialog[^>]*aria-labelledby="([^"]+)"/);
    expect(dialog).not.toBeNull();
    expect(body).toMatch(new RegExp(`<h2[^>]*id="${dialog![1]}"[^>]*>Add channel</h2>`));
    expect(body).toContain('<p>Form</p>');
    expect(body).toContain('<p>Save</p>');
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
