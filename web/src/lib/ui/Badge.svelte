<script lang="ts">
  import { severityTone } from './format';
  let { severity }: { severity: string | null | undefined } = $props();
  let tone = $derived(severityTone(severity));
</script>
<span class="badge {tone}">{tone.toUpperCase()}</span>
<style>
  .badge { display: inline-block; border: 1px solid currentColor; border-radius: var(--r-badge); padding: 1px 7px; font-size: var(--text-xs); font-weight: 700; letter-spacing: .04em; white-space: nowrap; }
  .critical { color: var(--sev-critical); } .high { color: var(--sev-high); } .medium { color: var(--sev-medium); } .low { color: var(--sev-low); } .unknown { color: var(--sev-unknown); }
</style>
