<script lang="ts">let { rows = 4, label = 'Loading' }: { rows?: number; label?: string } = $props();</script>
<div class="skeleton" role="status" aria-label={label}>{#each Array(rows) as _, i}<span style:width="{100 - (i % 3) * 12}%"></span>{/each}</div>
<style>
  .skeleton { display: grid; gap: var(--s3); padding: var(--s4); }
  span { height: 36px; border-radius: var(--r-control); background: var(--panel-2); animation: pulse 1.4s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: .55; } }
</style>
