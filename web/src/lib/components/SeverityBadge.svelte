<script lang="ts">
  let { severity }: { severity: string } = $props();
  let name = $derived(['critical', 'high', 'medium', 'low'].includes(severity.toLowerCase()) ? severity.toLowerCase() : 'unknown');
</script>
<span class:critical={name === 'critical'} class:high={name === 'high'} class:medium={name === 'medium'} class:low={name === 'low'} class:unknown={name === 'unknown'}>{name[0].toUpperCase() + name.slice(1)}</span>
<style>
 span { font-size:.8rem; font-weight:700; white-space:nowrap; } .critical { color:var(--badge-text); background:var(--critical); border-radius:3px; padding:.18rem .4rem; } .high { color:var(--high); border:1px solid var(--high); border-radius:3px; padding:.12rem .35rem; } .medium { color:var(--medium); } .low { color:var(--low); } .unknown { color:var(--muted); }
</style>
