<script lang="ts">
  import Menu from './Menu.svelte';
  let { realms, selected, change }: { realms: string[]; selected: string[]; change: (next: string[]) => void } = $props();
</script>
<Menu label="Filter realms" align="end">
  {#snippet trigger()}<span class="trigger">Realm: <b>{selected.length ? selected.join(', ') : 'All'}</b> ▾</span>{/snippet}
  <strong>Realms</strong>
  <label><input type="checkbox" checked={selected.length === 0} onchange={() => change([])} /> All my realms</label>
  {#each realms as realm}<label><input type="checkbox" checked={selected.includes(realm)} onchange={(e) => change(e.currentTarget.checked ? [...selected, realm] : selected.filter(r => r !== realm))} /> {realm}</label>{/each}
</Menu>
<style>
  .trigger { display: inline-flex; gap: 4px; border: 1px solid var(--border); background: var(--panel); border-radius: var(--r-control); padding: 7px 10px; font-size: var(--text-md); color: var(--muted); white-space: nowrap; }
  b { color: var(--text); font-weight: 600; max-width: 180px; overflow: hidden; text-overflow: ellipsis; }
  label { display: flex; gap: var(--s2); align-items: center; margin-top: var(--s2); white-space: nowrap; }
</style>
