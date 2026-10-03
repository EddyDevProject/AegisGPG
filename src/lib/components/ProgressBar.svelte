<script lang="ts">
  let { done, total }: { done: number; total: number } = $props();
  const pct = $derived(total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0);
</script>

<div class="h-2 w-full overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800" role="progressbar" aria-valuenow={pct} aria-valuemin="0" aria-valuemax="100">
  <div class="h-full bg-accent transition-[width] duration-100" style:width="{pct}%"></div>
</div>
<div class="mt-1 text-right text-xs text-zinc-500">{pct}%</div>
