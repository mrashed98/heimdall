<script lang="ts">
  import { niceMax } from './trends';
  type Point = { day: string; value: number | null };
  let { points, label, color, compact = false }: { points: Point[]; label: string; color: string; compact?: boolean } = $props();
  let width = $state(0), hover = $state<number | null>(null);
  const height = $derived(compact ? 36 : 140);
  const pad = $derived(compact ? { l: 2, r: 30, t: 6, b: 6 } : { l: 30, r: 34, t: 10, b: 22 });
  const max = $derived(niceMax(Math.max(0, ...points.map(p => p.value ?? 0))));
  const step = $derived(points.length > 1 ? (width - pad.l - pad.r) / (points.length - 1) : 0);
  const x = (i: number) => pad.l + i * step;
  const y = (v: number) => pad.t + (1 - v / max) * (height - pad.t - pad.b);
  // Missing days break the line; a day with no neighbours is drawn as a dot.
  const path = $derived(points.map((p, i) => p.value === null ? '' : `${points[i - 1]?.value == null ? 'M' : 'L'}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(''));
  const lone = $derived(points.flatMap((p, i) => p.value !== null && points[i - 1]?.value == null && points[i + 1]?.value == null ? [i] : []));
  const last = $derived(points.reduce((found, p, i) => p.value === null ? found : i, -1));
  const short = (day: string) => new Date(day + 'T00:00:00Z').toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });
  const summary = $derived(last < 0 ? `${label}: no data yet` : `${label}: ${points[last]!.value} on ${short(points[last]!.day)}; peak ${Math.max(...points.map(p => p.value ?? 0))} over ${points.length} days`);
  function move(e: PointerEvent) {
    if (!step) return;
    const box = (e.currentTarget as HTMLElement).getBoundingClientRect();
    hover = Math.min(points.length - 1, Math.max(0, Math.round((e.clientX - box.left - pad.l) / step)));
  }
</script>
<!-- Pointer-only crosshair; keyboard and screen-reader users get the summary and the table view. -->
<div class="chart" bind:clientWidth={width} role="presentation" onpointermove={move} onpointerleave={() => hover = null}>
  {#if width}
    <svg {width} {height} role="img" aria-label={summary}>
      {#if !compact}
        {#each [0, max] as tick}<line class="grid" x1={pad.l} x2={width - pad.r} y1={y(tick)} y2={y(tick)} /><text class="axis" x={pad.l - 6} y={y(tick) + 4} text-anchor="end">{tick}</text>{/each}
        {#if points.length}<text class="axis" x={pad.l} y={height - 4}>{short(points[0]!.day)}</text><text class="axis" x={width - pad.r} y={height - 4} text-anchor="end">{short(points[points.length - 1]!.day)}</text>{/if}
      {/if}
      {#if hover !== null}<line class="cross" x1={x(hover)} x2={x(hover)} y1={pad.t} y2={height - pad.b} />{/if}
      <path d={path} style:stroke={color} />
      {#each lone as i}<circle class="dot" style:fill={color} cx={x(i)} cy={y(points[i]!.value!)} r="3" />{/each}
      {#if last >= 0}<circle class="end" style:fill={color} cx={x(last)} cy={y(points[last]!.value!)} r="4" /><text class="value" x={x(last) + 8} y={y(points[last]!.value!) + 4}>{points[last]!.value}</text>{/if}
    </svg>
    {#if hover !== null}
      {@const p = points[hover]!}
      <div class="tip" style:left="{Math.min(Math.max(x(hover), 60), width - 60)}px"><strong>{p.value ?? 'No snapshot'}</strong><span>{short(p.day)}</span></div>
    {/if}
  {/if}
</div>
<style>
  .chart { position: relative; min-width: 0; }
  svg { display: block; overflow: visible; touch-action: pan-y; }
  path { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
  .end { stroke: var(--panel); stroke-width: 2; }
  .grid { stroke: var(--border); stroke-width: 1; }
  .cross { stroke: var(--muted); stroke-width: 1; }
  text { font-size: 11px; fill: var(--muted); font-variant-numeric: tabular-nums; }
  .value { fill: var(--text); font-weight: 600; font-size: 12px; }
  .tip { position: absolute; top: -6px; transform: translate(-50%, -100%); display: grid; justify-items: center; gap: 1px; padding: 4px 8px; border: 1px solid var(--border); border-radius: 6px; background: var(--panel); font-size: var(--text-sm); white-space: nowrap; pointer-events: none; box-shadow: 0 2px 8px rgb(0 0 0 / .12); }
  .tip span { color: var(--muted); font-size: 11px; }
</style>
