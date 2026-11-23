<script lang="ts">
  let { retry, message = 'Something went wrong loading this.' }: { retry?: () => void; message?: string } = $props();
</script>
<div class="error" role="alert">
  <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M12 3l9 16H3zM12 10v4M12 17h.01" /></svg>
  <strong>{message}</strong>{#if retry}<button onclick={retry}>Try again</button>{/if}
</div>
<style>
  .error { display: grid; justify-items: center; gap: var(--s2); text-align: center; padding: 48px var(--s5); }
  svg { color: var(--sev-high); }
  button { border: 1px solid var(--border); background: var(--panel-2); border-radius: var(--r-control); padding: 7px 14px; font-weight: 600; }
</style>
