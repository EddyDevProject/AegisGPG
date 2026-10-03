<script lang="ts">
  import { trustLabels } from "../stores.svelte";
  import type { Trust } from "../types";

  let { level, prefix = "" }: { level: Trust; prefix?: string } = $props();

  const tone: Record<Trust, string> = {
    ultimate: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
    full: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
    marginal: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
    none: "bg-red-500/15 text-red-700 dark:text-red-400",
    unknown: "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400",
  };
</script>

<span class="rounded px-1.5 py-0.5 text-xs {tone[level]}">{prefix}{trustLabels[level]}</span>
