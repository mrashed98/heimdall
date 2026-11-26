import { describe, expect, it } from 'vitest';
import { CHANNEL_TYPES, channelBody, generateSecret, healthLabel, patchBody } from './channels';

const common = { name: 'ops', realms: ['prod'], min_severity: 'high', digest: null };

describe('channel forms', () => {
  it('lists every channel type in order', () => {
    expect(CHANNEL_TYPES.map(t => t.id)).toEqual(['teams', 'slack', 'discord', 'mattermost', 'telegram', 'pagerduty', 'alertmanager', 'email', 'webhook', 'jira']);
  });
  it('marks every server-side secret as a secret field', () => {
    const secrets = (id: string) => CHANNEL_TYPES.find(t => t.id === id)!.fields.filter(f => f.kind === 'secret').map(f => f.key);
    // Mirrors secret_fields in src/notify/store.rs, every type.
    expect(secrets('teams')).toEqual(['webhook']);
    expect(secrets('slack')).toEqual(['webhook']);
    expect(secrets('discord')).toEqual(['webhook']);
    expect(secrets('telegram')).toEqual(['bot_token']);
    expect(secrets('pagerduty')).toEqual(['routing_key']);
    expect(secrets('alertmanager')).toEqual(['username', 'password', 'bearer_token']);
    expect(secrets('email')).toEqual(['username', 'password']);
    expect(secrets('webhook')).toEqual(['url', 'secret']);
    expect(secrets('mattermost')).toEqual(['webhook']);
    expect(secrets('jira')).toEqual(['username', 'token']);
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
  it('trims outer whitespace from SMTP hosts on create', () => {
    const body = channelBody('email', { host: ' \tsmtp.example.com\n ' }, common);
    expect(body).toHaveProperty('settings', { host: 'smtp.example.com' });
  });
  it('trims outer whitespace from SMTP hosts on patch', () => {
    const body = patchBody('email', { host: ' \tsmtp.example.com\n ' }, {}, common);
    expect(body).toHaveProperty('settings', { host: 'smtp.example.com' });
  });

  const createEmail = (port: string | number | undefined) => channelBody('email', { port }, common);
  const patchEmail = (port: string | number | undefined) => patchBody('email', { port }, {}, common);

  describe.each([{ build: createEmail, verb: 'POST' }, { build: patchEmail, verb: 'PATCH' }])('$verb numeric settings', ({ build }) => {
    it('accepts a bound number value', () => {
      expect(build(587)).toMatchObject({ settings: { port: 587 } });
    });
    it.each(['', ' \t', undefined])('omits a blank or unset port (%j)', port => {
      expect(build(port)).toHaveProperty('settings', {});
    });
    it.each(['587xyz', 'NaN', 'Infinity', '1e309', NaN, Infinity, -Infinity])('rejects an invalid port (%s)', port => {
      expect(() => build(port)).toThrow('Port must be a finite number.');
    });
  });

  it('channelBody omits whitespace-only optional secrets and preserves nonblank secret bytes', () => {
    const body = channelBody('email', { username: ' \t', password: ' example ' }, common);
    expect(body).toHaveProperty('secrets', { password: ' example ' });
  });
  it.each(['', ' \t', undefined])('patchBody refuses a blank secret replacement (%j)', password => {
    expect(() => patchBody('email', { password }, { password: 'replace' }, common)).toThrow('Password must not be empty.');
  });
  it('patchBody sends a nonblank secret replacement byte for byte', () => {
    expect(patchBody('email', { password: ' p ' }, { password: 'replace' }, common)).toHaveProperty('secrets', { password: ' p ' });
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
    expect(healthLabel({ queued: 0, last_sent_at: '2026-11-24T11:00:00Z', failing: 'HTTP 500' }, now)).toEqual({ text: 'Failing: HTTP 500', tone: 'warn' });
    expect(healthLabel({ queued: 0, last_sent_at: '2026-11-24T11:55:00Z', failing: null }, now)).toEqual({ text: 'Sent 5m ago', tone: 'ok' });
    expect(healthLabel({ queued: 0, last_sent_at: null, failing: null }, now)).toEqual({ text: 'No deliveries yet', tone: 'muted' });
    expect(healthLabel({ queued: 3, last_sent_at: null, failing: 'x' }, now)).toEqual({ text: 'Failing: x · 3 queued', tone: 'warn' });
  });
});
