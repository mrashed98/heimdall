<script lang="ts" module>
  export const icons = {
    findings: 'M12 3l9 16H3zM12 10v4M12 17h.01',
    overview: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
    inventory: 'M3 7l9-4 9 4-9 4zM3 7v10l9 4 9-4V7',
    releases: 'M3 12V3h9l9 9-9 9zM7.5 7.5h.01',
    oaths: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
    settings: 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1',
    search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4',
    copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
    external: 'M14 4h6v6M20 4l-9 9M18 14v6H4V6h6',
    back: 'M15 18l-6-6 6-6'
  } as const;
  export type IconName = keyof typeof icons;
</script>
<script lang="ts">
  let { name, size = 20 }: { name: IconName; size?: number } = $props();
</script>
<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={icons[name]} /></svg>
