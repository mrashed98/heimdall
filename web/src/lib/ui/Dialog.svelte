<script lang="ts">
  import type { Snippet } from 'svelte';
  let { open = $bindable(false), title, children, actions, onclose }: { open: boolean; title: string; children: Snippet; actions?: Snippet; onclose?: () => void } = $props();
  const uid = $props.id();
  let el = $state<HTMLDialogElement>();
  // A modal <dialog> traps focus and closes on Escape; its close event keeps `open` in step.
  $effect(() => {
    if (!el) return;
    if (open && !el.open) el.showModal();
    else if (!open && el.open) el.close();
  });

  function handleClose() {
    // The close event is queued, so the dialog may already be open again.
    if (el?.open) return;
    open = false;
    onclose?.();
  }
</script>
<dialog bind:this={el} aria-labelledby={uid} onclose={handleClose}>
  <header><h2 id={uid}>{title}</h2></header>
  <div class="body">{@render children()}</div>
  {#if actions}<footer>{@render actions()}</footer>{/if}
</dialog>
<style>
  dialog { width: min(520px, calc(100vw - 2 * var(--s4))); max-height: calc(100vh - 2 * var(--s5)); padding: 0; background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: var(--r-card); box-shadow: 0 24px 70px var(--shadow); overflow: auto; }
  dialog::backdrop { background: var(--shadow); }
  header { padding: var(--s4) var(--s5) 0; }
  h2 { font-size: var(--text-lg); margin: 0; }
  .body { padding: var(--s4) var(--s5); display: grid; gap: var(--s3); }
  footer { display: flex; justify-content: flex-end; gap: var(--s2); padding: var(--s3) var(--s5) var(--s4); border-top: 1px solid var(--border); }
</style>
