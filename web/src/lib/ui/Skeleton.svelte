<script lang="ts">let { rows = 4, label = 'Loading' }: { rows?: number; label?: string } = $props();</script>
<div class="skeleton" role="status"><span class="sr">{label}</span>{#each Array(rows) as _, i}<span aria-hidden="true" class="bar" style:width="{100 - (i % 3) * 12}%"></span>{/each}</div>
<style>
  .skeleton { display: grid; gap: var(--s3); padding: var(--s4); }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
  .bar { height: 36px; border-radius: var(--r-control); background: var(--panel-2); animation: pulse 1.4s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: .55; } }
</style>
