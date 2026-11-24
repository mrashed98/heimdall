<script lang="ts">
  import { api, ApiError } from './api';
  import { CHANNEL_TYPES, channelBody, generateSecret, healthLabel, patchBody, type ChannelCommon, type ChannelHealth, type Field, type SecretChange } from './channels';
  import { Badge, Button, DataTable, Dialog, EmptyState, ErrorState, Input, Menu, Panel, Pill, SEVERITIES, Select, Skeleton } from './ui';

  type Channel = Omit<ChannelCommon, 'digest'> & {
    id: number | null;
    source: 'config' | 'ui';
    type: string;
    digest: boolean;
    settings: Record<string, string | number | string[] | null>;
    secrets: Record<string, { set: boolean }>;
    missing_env: string[];
    state: 'ok' | 'key_missing' | 'unreadable' | 'name_clash';
    health: ChannelHealth;
  };
  type ChannelList = { management_enabled: boolean; channels: Channel[] };
  type ChannelType = (typeof CHANNEL_TYPES)[number];
  type Editor = {
    type: ChannelType;
    channel?: Channel;
    name: string;
    realms: string[];
    severity: string;
    digest: string;
    digestChanged: boolean;
    values: Record<string, string>;
    changes: Record<string, SecretChange>;
    visible: Record<string, boolean>;
  };
  type Removal = { id: number; name: string; queued: number | null; error: string };
  type TestResult = { pending: boolean; text: string; failed?: boolean };

  const endpoint = '/api/v1/channels';
  const stateLabels = {
    ok: '',
    key_missing: 'Key missing',
    unreadable: 'Secret unreadable: re-enter it',
    name_clash: 'Name clash with config: delete this channel',
  };
  const formId = $props.id();
  let { availableRealms }: { availableRealms: string[] } = $props();
  let list = $state<ChannelList | null>(null);
  let failed = $state(false);
  let revision = $state(0);
  let results = $state<Record<string, TestResult>>({});
  let editor = $state<Editor | null>(null);
  let editError = $state('');
  let copyMessage = $state('');
  let removal = $state<Removal | null>(null);
  let busy = $state(false);
  let realmOptions = $derived([...new Set([...availableRealms, ...(editor?.channel?.realms ?? [])])]);

  $effect(() => {
    revision;
    const request = new AbortController();
    failed = false;
    api<ChannelList>(endpoint, { signal: request.signal }).then(data => {
      if (!request.signal.aborted) list = data;
    }).catch(() => {
      if (!request.signal.aborted) failed = true;
    });
    return () => request.abort();
  });

  function errorText(error: unknown, fallback: string) {
    if (error instanceof TypeError) return error.message;
    return error instanceof ApiError && error.code ? error.code : fallback;
  }

  function rowKey(channel: Channel) {
    return channel.id === null ? `config:${channel.name}` : `ui:${channel.id}`;
  }

  async function testChannel(channel: Channel) {
    const key = rowKey(channel);
    if (channel.state === 'name_clash' || results[key]?.pending) return;
    results[key] = { pending: true, text: 'Sending test alert…' };
    try {
      await api(`${endpoint}/${encodeURIComponent(channel.name)}/test`, { method: 'POST' });
      results[key] = { pending: false, text: 'Test alert sent.' };
    } catch (error) {
      results[key] = { pending: false, failed: true, text: errorText(error, 'Could not send the test alert.') };
    }
  }

  function closeMenu(event: MouseEvent) {
    const menu = (event.currentTarget as HTMLElement).closest('details');
    menu?.querySelector('summary')?.focus();
    if (menu) menu.open = false;
  }

  function openEditor(type: ChannelType, channel?: Channel) {
    editor = {
      type,
      channel,
      name: channel?.name ?? '',
      realms: [...(channel?.realms ?? [])],
      severity: channel?.min_severity ?? 'high',
      digest: channel ? (channel.digest ? 'on' : 'off') : 'default',
      digestChanged: false,
      values: Object.fromEntries(type.fields.map(field => {
        const value = field.kind === 'secret' ? null : channel?.settings[field.key];
        return [field.key, Array.isArray(value) ? value.join('\n') : String(value ?? '')];
      })),
      changes: {},
      visible: {},
    };
    editError = '';
    copyMessage = '';
  }

  function changeSecret(draft: Editor, field: Field, change: SecretChange) {
    draft.changes[field.key] = change;
    draft.values[field.key] = '';
    draft.visible[field.key] = false;
    copyMessage = '';
  }

  function generate(draft: Editor, field: Field) {
    draft.values[field.key] = generateSecret();
    draft.visible[field.key] = true;
    copyMessage = '';
  }

  async function copySecret(draft: Editor, field: Field) {
    let message: string;
    try {
      await navigator.clipboard.writeText(draft.values[field.key]);
      message = 'Copied.';
    } catch {
      message = 'Could not copy. Select and copy the value above.';
    }
    if (editor === draft) copyMessage = message;
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    const draft = editor;
    if (!draft || busy) return;
    editError = '';
    const channel = draft.channel;
    if (channel?.state === 'unreadable' && draft.type.fields.some(field =>
      field.kind === 'secret' && channel.secrets[field.key]?.set && !draft.changes[field.key]
    )) {
      editError = 'Replace or remove each unreadable secret before saving.';
      return;
    }
    const common: ChannelCommon = {
      name: draft.name,
      realms: [...draft.realms],
      min_severity: draft.severity,
      digest: draft.digest === 'default' ? null : draft.digest === 'on',
    };
    busy = true;
    try {
      // The list only returns the effective digest. Omit it on unrelated edits to retain the stored preference.
      const body = channel
        ? { ...patchBody(draft.type.id, draft.values, draft.changes, common), digest: draft.digestChanged ? common.digest : undefined }
        : channelBody(draft.type.id, draft.values, common);
      await api(channel ? `${endpoint}/${channel.id}` : endpoint, {
        method: channel ? 'PATCH' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (editor === draft) editor = null;
      revision++;
    } catch (error) {
      if (editor === draft) editError = errorText(error, 'Could not save the channel. Please try again.');
    } finally {
      busy = false;
    }
  }

  function openRemoval(channel: Channel) {
    if (channel.id === null) return;
    removal = { id: channel.id, name: channel.name, queued: null, error: '' };
    void loadQueued(removal);
  }

  async function loadQueued(target: Removal) {
    target.error = '';
    try {
      const result = await api<{ queued: number }>(`${endpoint}/${target.id}/queued`);
      if (removal === target) target.queued = result.queued;
    } catch (error) {
      if (removal === target) target.error = errorText(error, 'Could not load the queued alert count.');
    }
  }

  async function deleteChannel() {
    const target = removal;
    if (!target || target.queued === null || busy) return;
    busy = true;
    target.error = '';
    try {
      await api(`${endpoint}/${target.id}`, { method: 'DELETE' });
      delete results[`ui:${target.id}`];
      if (removal === target) removal = null;
      revision++;
    } catch (error) {
      if (removal === target) target.error = errorText(error, 'Could not delete the channel. Please try again.');
    } finally {
      busy = false;
    }
  }
</script>

<section class="channels" aria-label="Alert channels">
  <div class="heading">
    <p>Findings go out as grouped alerts to every channel that covers their realm.</p>
    {#if list?.management_enabled}
      <div class="add-menu">
        <Menu label="Add channel" align="end">
          {#snippet trigger()}<span class="add-trigger">Add channel <span aria-hidden="true">▾</span></span>{/snippet}
          <div class="type-options">
            {#each CHANNEL_TYPES as type (type.id)}
              <Button size="sm" variant="ghost" disabled={busy} onclick={(event) => { closeMenu(event); openEditor(type); }}>{type.label}</Button>
            {/each}
          </div>
        </Menu>
      </div>
    {:else if list}
      <p class="key-notice">Set <code>HEIMDALL_SECRET_KEY</code> to add channels here. See the <a href="https://mrashed98.github.io/heimdall/guides/alert-channels/">alert channels guide</a>.</p>
    {/if}
  </div>

  <Panel flush>
    {#if failed}
      <ErrorState message="Could not load alert channels." retry={() => revision++} />
    {:else if !list}
      <Skeleton />
    {:else if !list.channels.length}
      <EmptyState title="No alert channels" body="None yet. Findings stay pending and go out as grouped alerts once a channel exists.">
        {#snippet action()}
          {#if list?.management_enabled}
            <div class="type-buttons">
              {#each CHANNEL_TYPES as type (type.id)}
                <Button size="sm" disabled={busy} onclick={() => openEditor(type)}>{type.label}</Button>
              {/each}
            </div>
          {/if}
        {/snippet}
      </EmptyState>
    {:else}
      <DataTable label="Alert channels">
        <thead><tr>
          <th scope="col">Name</th><th scope="col">Type</th><th scope="col">Realms</th><th scope="col">Min severity</th>
          <th scope="col">Digest</th><th scope="col">Last delivery</th><th scope="col">Source</th><th scope="col">Actions</th>
        </tr></thead>
        <tbody>
          {#each list.channels as channel (rowKey(channel))}
            {@const type = CHANNEL_TYPES.find(type => type.id === channel.type)}
            {@const result = results[rowKey(channel)]}
            <tr>
              <td>
                <strong>{channel.name}</strong>
                {#if channel.missing_env.length}<small class="warn">Missing: {channel.missing_env.join(', ')}</small>{/if}
                {#if stateLabels[channel.state]}<small class="warn">{stateLabels[channel.state]}</small>{/if}
              </td>
              <td>{type?.label ?? channel.type}</td>
              <td>{channel.realms.length ? channel.realms.join(', ') : 'All'}</td>
              <td><Badge severity={channel.min_severity} /></td>
              <td>{channel.digest ? 'On' : 'Off'}</td>
              <td>
                {#if channel.state === 'name_clash'}
                  <span class="muted">—</span>
                {:else}
                  {@const health = healthLabel(channel.health, new Date())}
                  <span class={health.tone}>{health.text}</span>
                {/if}
              </td>
              <td>
                {#if channel.source === 'config'}
                  <span title="Defined in heimdall.yaml"><Pill tone="gold">config</Pill></span>
                {:else}<Pill>UI</Pill>{/if}
              </td>
              <td>
                <div class="row-actions">
                  <Button size="sm" aria-label={`Test ${channel.name}`} disabled={channel.state === 'name_clash' || result?.pending} onclick={() => testChannel(channel)}>Test</Button>
                  {#if channel.source === 'ui'}
                    {#if type}<Button size="sm" aria-label={`Edit ${channel.name}`} disabled={busy || !list?.management_enabled} onclick={() => openEditor(type, channel)}>Edit</Button>{/if}
                    <div class="row-menu">
                      <Menu label={`More actions for ${channel.name}`} align="end">
                        {#snippet trigger()}<span class="more-trigger" aria-hidden="true">⋯</span>{/snippet}
                        <Button size="sm" variant="danger" disabled={busy} onclick={(event) => { closeMenu(event); openRemoval(channel); }}>Delete</Button>
                      </Menu>
                    </div>
                  {/if}
                </div>
                <div class="test-result" class:warn={result?.failed} role="status">{result?.text ?? ''}</div>
              </td>
            </tr>
          {/each}
        </tbody>
      </DataTable>
    {/if}
  </Panel>
</section>

{#if editor}
  {@const draft = editor}
  <Dialog open={true} title={draft.channel ? `Edit ${draft.channel.name}` : `Add ${draft.type.label} channel`} onclose={() => editor = null}>
    <form id={formId} onsubmit={save}>
      <Input label="Name" bind:value={draft.name} disabled={!!draft.channel} required />
      <fieldset class="realms">
        <legend>Realms</legend>
        <p class="muted">When none are selected, this channel covers all realms.</p>
        <div class="realm-options">
          {#each realmOptions as realm (realm)}
            <label><input type="checkbox" bind:group={draft.realms} value={realm} />{realm}{#if !availableRealms.includes(realm)} <span class="warn">(no longer available)</span>{/if}</label>
          {/each}
        </div>
      </fieldset>
      <div class="form-pair">
        <Select label="Minimum severity" bind:value={draft.severity}>
          {#each SEVERITIES as severity}<option value={severity}>{severity}</option>{/each}
        </Select>
        <Select label="Digest" bind:value={draft.digest} onchange={() => draft.digestChanged = true}>
          <option value="default">Default</option><option value="on">On</option><option value="off">Off</option>
        </Select>
      </div>
      {#if draft.channel?.state === 'unreadable'}
        <p class="warn">Replace or remove each unreadable secret before saving. Required secrets must be replaced.</p>
      {/if}
      {#each draft.type.fields as field (field.key)}
        {#if field.kind === 'secret'}
          {@const saved = draft.channel?.secrets[field.key]?.set}
          {@const unreadable = saved && draft.channel?.state === 'unreadable'}
          {@const change = draft.changes[field.key] ?? 'keep'}
          {@const signing = draft.type.id === 'webhook' && field.key === 'secret'}
          <div class="secret-field">
            {#if saved && change !== 'replace'}
              <span class="field-label">{field.label}</span>
              <div class="controls">
                {#if change === 'remove'}
                  <span class="muted">Will be removed</span>
                {:else if unreadable}
                  <span class="warn">Unreadable</span>
                {:else}
                  <span class="muted">•••••••• Saved</span>
                {/if}
                <Button size="sm" aria-label={`Replace ${field.label}`} onclick={() => changeSecret(draft, field, 'replace')}>Replace</Button>
                {#if change === 'keep' && !field.required}
                  <Button size="sm" variant="ghost" aria-label={`Remove ${field.label}`} onclick={() => changeSecret(draft, field, 'remove')}>Remove</Button>
                {:else if change === 'remove' && !unreadable}
                  <Button size="sm" variant="ghost" aria-label={`Keep ${field.label}`} onclick={() => changeSecret(draft, field, 'keep')}>Keep saved</Button>
                {/if}
              </div>
            {:else}
              <Input label={field.label} type={draft.visible[field.key] ? 'text' : 'password'} bind:value={draft.values[field.key]} required={field.required || change === 'replace'} autocomplete="new-password" spellcheck={false} hint="This value can't be shown again." />
              <div class="controls">
                <Button size="sm" variant="ghost" aria-label={`${draft.visible[field.key] ? 'Hide' : 'Show'} ${field.label}`} onclick={() => draft.visible[field.key] = !draft.visible[field.key]}>{draft.visible[field.key] ? 'Hide' : 'Show'}</Button>
                {#if signing}
                  <Button size="sm" onclick={() => generate(draft, field)}>Generate</Button>
                  {#if draft.visible[field.key] && draft.values[field.key]}<Button size="sm" onclick={() => copySecret(draft, field)}>Copy</Button>{/if}
                {/if}
                {#if saved && !field.required}
                  <Button size="sm" variant="ghost" aria-label={`Remove ${field.label}`} onclick={() => changeSecret(draft, field, 'remove')}>Remove</Button>
                {/if}
                {#if saved && !unreadable}
                  <Button size="sm" variant="ghost" aria-label={`Keep ${field.label}`} onclick={() => changeSecret(draft, field, 'keep')}>Keep saved</Button>
                {/if}
              </div>
              {#if signing}<div class="test-result" role="status">{copyMessage}</div>{/if}
            {/if}
          </div>
        {:else if field.kind === 'select'}
          <Select label={field.label} bind:value={draft.values[field.key]} required={field.required}>
            {#if !field.required}<option value="">Default</option>{/if}
            {#each field.options ?? [] as option}<option value={option}>{option}</option>{/each}
          </Select>
        {:else if field.kind === 'list'}
          <label class="field-label">
            {field.label}
            <textarea bind:value={draft.values[field.key]} required={field.required} rows="3" aria-describedby={`${formId}-${field.key}-hint`}></textarea>
          </label>
          <small class="list-hint muted" id={`${formId}-${field.key}-hint`}>{field.hint}</small>
        {:else}
          <Input label={field.label} type={field.kind} bind:value={draft.values[field.key]} required={field.required} hint={field.hint} />
        {/if}
      {/each}
      {#if editError}<p class="warn" role="alert">{editError}</p>{/if}
    </form>
    {#snippet actions()}
      <Button variant="ghost" onclick={() => editor = null}>Cancel</Button>
      <Button type="submit" form={formId} variant="primary" disabled={busy}>{draft.channel ? 'Save changes' : 'Create channel'}</Button>
    {/snippet}
  </Dialog>
{/if}

{#if removal}
  {@const target = removal}
  <Dialog open={true} title={`Delete ${target.name}?`} onclose={() => removal = null}>
    <p>Alerts for these realms will no longer go to this channel.{target.queued !== null ? ` ${target.queued} queued ${target.queued === 1 ? 'alert' : 'alerts'} will be discarded.` : ''}</p>
    {#if target.error}
      <p class="warn" role="alert">{target.error}</p>
      {#if target.queued === null}<div><Button size="sm" onclick={() => loadQueued(target)}>Try again</Button></div>{/if}
    {:else if target.queued === null}
      <p class="muted" role="status">Loading queued alert count…</p>
    {/if}
    {#snippet actions()}
      <Button variant="ghost" onclick={() => removal = null}>Cancel</Button>
      <Button variant="danger" disabled={busy || target.queued === null} onclick={deleteChannel}>Delete channel</Button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .channels { display: grid; gap: var(--s3); min-width: 0; }
  .heading { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: var(--s2) var(--s4); color: var(--muted); font-size: var(--text-sm); }
  p { margin: 0; }
  .add-menu { margin-inline-start: auto; }
  .add-trigger, .more-trigger { display: inline-flex; gap: var(--s2); align-items: center; padding: 5px 10px; border: 1px solid var(--border); border-radius: var(--r-control); background: var(--panel-2); color: var(--text); font-size: var(--text-sm); font-weight: 600; white-space: nowrap; }
  .add-trigger { padding: 8px 14px; background: var(--gold); border-color: var(--gold); color: var(--on-gold); }
  .add-menu :global(summary), .row-menu :global(summary) { cursor: pointer; }
  .type-options { display: grid; gap: var(--s1); }
  .type-options :global(button) { justify-content: flex-start; color: var(--text); }
  .key-notice { border: 1px solid var(--gold-line); border-radius: var(--r-control); background: var(--gold-soft); padding: var(--s2) var(--s3); }
  .key-notice a { text-decoration: underline; }
  .type-buttons, .controls, .realm-options { display: flex; flex-wrap: wrap; align-items: center; gap: var(--s2); }
  .type-buttons { justify-content: center; }
  .row-actions { display: flex; align-items: flex-start; gap: var(--s1); }
  .row-menu :global(.pop) { position: static; min-width: 0; padding: var(--s1); box-shadow: none; }
  th { white-space: nowrap; }
  td { overflow-wrap: break-word; }
  td small { display: block; margin-top: var(--s1); }
  .test-result { font-size: var(--text-sm); }
  .test-result:not(:empty) { margin-top: var(--s1); }
  .warn { color: var(--sev-high); }
  .muted { color: var(--muted); }
  .ok { color: var(--ok); }
  form, .secret-field { display: grid; gap: var(--s3); min-width: 0; }
  .secret-field { gap: var(--s1); }
  .form-pair { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--s3); }
  .realms { display: grid; gap: var(--s1); min-width: 0; border: 0; margin: 0; padding: 0; font-size: var(--text-sm); }
  .realms label { display: inline-flex; flex-wrap: wrap; align-items: center; column-gap: var(--s1); overflow-wrap: anywhere; }
  .realms input { accent-color: var(--gold); }
  legend, .field-label { color: var(--muted); font-weight: 600; font-size: var(--text-sm); padding: 0; }
  .field-label { display: grid; gap: var(--s1); }
  textarea { width: 100%; border: 1px solid var(--border); background: var(--bg); color: var(--text); border-radius: var(--r-control); padding: 8px 11px; font: inherit; font-weight: 400; resize: vertical; }
  .list-hint { margin-top: calc(-1 * var(--s2)); }
</style>
