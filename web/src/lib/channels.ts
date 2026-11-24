// Alert channel forms: the fields of each type and the API bodies they build.
import { relativeTime } from './ui/format';

export type FieldKind = 'text' | 'url' | 'number' | 'list' | 'select' | 'secret';
export interface Field { key: string; label: string; kind: FieldKind; required: boolean; options?: string[]; hint?: string }
export interface ChannelCommon { name: string; realms: string[]; min_severity: string; digest: boolean | null }
export type SecretChange = 'keep' | 'replace' | 'remove';

const f = (key: string, label: string, kind: FieldKind, required = false, extra: Partial<Field> = {}): Field => ({ key, label, kind, required, ...extra });
const webhook = [f('webhook', 'Webhook URL', 'secret', true)];

/** The secret fields here match the server's `secret_fields`. */
export const CHANNEL_TYPES: { id: string; label: string; fields: Field[] }[] = [
  { id: 'teams', label: 'Microsoft Teams', fields: webhook },
  { id: 'slack', label: 'Slack', fields: webhook },
  { id: 'discord', label: 'Discord', fields: webhook },
  { id: 'telegram', label: 'Telegram', fields: [
    f('bot_token', 'Bot token', 'secret', true), f('chat_id', 'Chat ID', 'text', true),
    f('api_url', 'API URL', 'url', false, { hint: 'Leave empty for api.telegram.org.' }),
  ] },
  { id: 'pagerduty', label: 'PagerDuty', fields: [
    f('routing_key', 'Routing key', 'secret', true),
    f('url', 'Events API URL', 'url', false, { hint: 'Leave empty for the PagerDuty default.' }),
  ] },
  { id: 'alertmanager', label: 'Alertmanager', fields: [
    f('url', 'Alertmanager URL', 'url', true), f('username', 'Username', 'secret'), f('password', 'Password', 'secret'),
    f('bearer_token', 'Bearer token', 'secret'), f('expire_after_hours', 'Expire after (hours)', 'number'),
  ] },
  { id: 'email', label: 'Email', fields: [
    f('host', 'SMTP host', 'text', true), f('port', 'Port', 'number'),
    f('security', 'Security', 'select', false, { options: ['starttls', 'tls', 'none'] }),
    f('from', 'From', 'text', true), f('to', 'To', 'list', true, { hint: 'One address per line, or comma separated.' }),
    f('username', 'Username', 'secret'), f('password', 'Password', 'secret'),
  ] },
  { id: 'webhook', label: 'Webhook', fields: [
    f('url', 'Endpoint URL', 'secret', true), f('secret', 'Signing secret', 'secret'),
  ] },
];

/** A form value the API would reject; its message names the field. */
export class FormError extends Error {}

function fields(type: string): Field[] {
  return CHANNEL_TYPES.find(t => t.id === type)?.fields ?? [];
}

type FieldValue = string | number | undefined;
type ChannelValues = Record<string, FieldValue>;
type SettingValue = string | number | string[];

function textValue(field: Field, value: FieldValue): string | undefined {
  if (typeof value === 'number') throw new FormError(`${field.label} must be text.`);
  return value;
}

function setting(field: Field, raw: FieldValue): SettingValue | undefined {
  if (field.kind === 'number') {
    if (raw === undefined || (typeof raw === 'string' && !raw.trim())) return undefined;
    const value = Number(raw);
    if (!Number.isFinite(value)) throw new FormError(`${field.label} must be a finite number.`);
    return value;
  }
  const value = textValue(field, raw)?.trim();
  if (!value) return undefined;
  if (field.kind === 'list') {
    const items = value.split(/[,\n]/).map(item => item.trim()).filter(Boolean);
    return items.length ? items : undefined;
  }
  return value;
}

function settings(type: string, values: ChannelValues): Record<string, SettingValue> {
  const result: Record<string, SettingValue> = {};
  for (const field of fields(type)) {
    if (field.kind === 'secret') continue;
    const value = setting(field, values[field.key]);
    if (value !== undefined) result[field.key] = value;
  }
  return result;
}

/** `POST /api/v1/channels` body. Omit blank optional secrets and preserve included values as entered. */
export function channelBody(type: string, values: ChannelValues, common: ChannelCommon): object {
  const secrets: Record<string, string> = {};
  for (const field of fields(type)) {
    if (field.kind !== 'secret') continue;
    const value = textValue(field, values[field.key]);
    if (value && (field.required || value.trim())) secrets[field.key] = value;
  }
  return { type, ...common, settings: settings(type, values), secrets };
}

/** `PATCH /api/v1/channels/{id}` body. Omit kept secrets and clear removed secrets with `null`. */
export function patchBody(type: string, values: ChannelValues, replaced: Record<string, SecretChange>, common: ChannelCommon): object {
  const secrets: Record<string, string | null> = {};
  for (const field of fields(type)) {
    if (field.kind !== 'secret') continue;
    const change = replaced[field.key] ?? 'keep';
    if (change === 'replace') {
      const value = textValue(field, values[field.key]) ?? '';
      if (!value.trim()) throw new FormError(`${field.label} must not be empty.`);
      secrets[field.key] = value;
    }
    else if (change === 'remove') secrets[field.key] = null;
  }
  const { realms, min_severity, digest } = common;
  return { realms, min_severity, digest, settings: settings(type, values), secrets };
}

/** A random signing secret: 32 bytes as 64 lowercase hex characters. */
export function generateSecret(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
}

export interface ChannelHealth { queued: number; last_sent_at: string | null; failing: string | null }

/** One line of channel health for the list. */
export function healthLabel(h: ChannelHealth, now: Date): { text: string; tone: 'ok' | 'warn' | 'muted' } {
  const base = h.failing !== null ? { text: `Failing: ${h.failing}`, tone: 'warn' as const }
    : h.last_sent_at ? { text: `Sent ${relativeTime(h.last_sent_at, now)}`, tone: 'ok' as const }
    : { text: 'No deliveries yet', tone: 'muted' as const };
  return h.queued > 0 ? { ...base, text: `${base.text} · ${h.queued} queued` } : base;
}
