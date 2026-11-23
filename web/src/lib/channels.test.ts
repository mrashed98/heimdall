import { describe, expect, it } from 'vitest';
import { CHANNEL_TYPES, channelBody, generateSecret, healthLabel, patchBody } from './channels';

const common = { name: 'ops', realms: ['prod'], min_severity: 'high', digest: null };

describe('channel forms', () => {
  it('lists every channel type in order', () => {
    expect(CHANNEL_TYPES.map(t => t.id)).toEqual(['teams', 'slack', 'discord', 'telegram', 'pagerduty', 'alertmanager', 'email', 'webhook']);
  });
  it('marks every server-side secret as a secret field', () => {
    const secrets = (id: string) => CHANNEL_TYPES.find(t => t.id === id)!.fields.filter(f => f.kind === 'secret').map(f => f.key);
    expect(secrets('slack')).toEqual(['webhook']);
    expect(secrets('alertmanager')).toEqual(['username', 'password', 'bearer_token']);
    expect(secrets('email')).toEqual(['username', 'password']);
    expect(secrets('webhook')).toEqual(['url', 'secret']);
  });
  it('requires email recipients and lists the supported security modes', () => {
    const fields = CHANNEL_TYPES.find(t => t.id === 'email')!.fields;
    expect(fields.find(f => f.key === 'to')).toMatchObject({ kind: 'list', required: true });
    expect(fields.find(f => f.key === 'security')?.options).toEqual(['starttls', 'tls', 'none']);
  });
  it('channelBody splits secrets from settings and drops empty optionals', () => {
    expect(channelBody('slack', { webhook: 'https://x' }, common)).toEqual({
      type: 'slack', name: 'ops', realms: ['prod'], min_severity: 'high', digest: null, settings: {}, secrets: { webhook: 'https://x' },
    });
    const tg = channelBody('telegram', { bot_token: 't', chat_id: ' 42 ', api_url: '  ' }, common) as Record<string, unknown>;
    expect(tg.settings).toEqual({ chat_id: '42' });
    expect(tg.secrets).toEqual({ bot_token: 't' });
  });
  it('channelBody parses numbers and lists', () => {
    const body = channelBody('email', { host: 'smtp', port: '587', security: 'starttls', from: 'h@x', to: 'a@x, b@x\nc@x\n', password: '' }, common) as Record<string, unknown>;
    expect(body.settings).toEqual({ host: 'smtp', port: 587, security: 'starttls', from: 'h@x', to: ['a@x', 'b@x', 'c@x'] });
    expect(body.secrets).toEqual({});
  });
  it('patchBody keeps, replaces and removes secrets', () => {
    const body = patchBody('alertmanager', { url: 'https://am', expire_after_hours: '12', username: 'u', password: 'p', bearer_token: '' },
      { username: 'keep', password: 'replace', bearer_token: 'remove' }, { ...common, digest: true }) as Record<string, unknown>;
    expect(body).toEqual({
      realms: ['prod'], min_severity: 'high', digest: true,
      settings: { url: 'https://am', expire_after_hours: 12 },
      secrets: { password: 'p', bearer_token: null },
    });
    expect(body).not.toHaveProperty('name');
    expect(body.secrets).not.toHaveProperty('username');
  });
  it('generateSecret returns 64 hex chars and differs per call', () => {
    const a = generateSecret();
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(generateSecret()).not.toBe(a);
  });
  it('healthLabel prefers failing, then last sent, then none', () => {
    const now = new Date('2026-11-24T12:00:00Z');
    expect(healthLabel({ queued: 0, last_sent_at: '2026-11-24T11:00:00Z', failing: 'HTTP 500' }, now)).toEqual({ text: 'Failing', tone: 'warn' });
    expect(healthLabel({ queued: 0, last_sent_at: '2026-11-24T11:55:00Z', failing: null }, now)).toEqual({ text: 'Sent 5m ago', tone: 'ok' });
    expect(healthLabel({ queued: 0, last_sent_at: null, failing: null }, now)).toEqual({ text: 'No deliveries yet', tone: 'muted' });
    expect(healthLabel({ queued: 3, last_sent_at: null, failing: 'x' }, now)).toEqual({ text: 'Failing · 3 queued', tone: 'warn' });
  });
});
