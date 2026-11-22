<script lang="ts">
  import { epssLabel } from '../findings';
  import { epssTone, epssWidth } from './format';
  let { score, percentile }: { score?: number | null; percentile?: number | null } = $props();
</script>
<span class="epss" title="Chance of exploitation in the next 30 days (FIRST EPSS)">
  <span class="track"><span class="fill {epssTone(score)}" style:width={epssWidth(score)}></span></span>
  <span class="label">{score == null ? 'No EPSS' : epssLabel(score, percentile)}</span>
</span>
<style>
  .epss { display: grid; gap: 4px; min-width: 96px; }
  .track { height: 6px; border-radius: 3px; background: var(--panel-2); overflow: hidden; }
  .fill { display: block; height: 100%; border-radius: 3px; }
  .critical { background: var(--sev-critical); } .high { background: var(--sev-high); } .low { background: var(--sky); } .unknown { background: transparent; }
  .label { font: var(--text-xs) var(--font-mono); color: var(--muted); white-space: nowrap; }
</style>
