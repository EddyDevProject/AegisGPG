<script lang="ts">
  import { fly } from "svelte/transition";
  import { toasts, dismissToast } from "../stores.svelte";

  const tone = {
    success: "border-emerald-500/40 bg-emerald-50 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-100",
    error: "border-red-500/40 bg-red-50 text-red-900 dark:bg-red-950 dark:text-red-100",
    info: "border-zinc-300 bg-white text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100",
  };
</script>

<div class="pointer-events-none fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2" aria-live="polite">
  {#each toasts as t (t.id)}
    <div
      transition:fly={{ x: 40, duration: 180 }}
      role={t.kind === "error" ? "alert" : "status"}
      class="pointer-events-auto flex items-start gap-2 rounded-lg border px-3 py-2 text-sm shadow-lg {tone[t.kind]}"
    >
      <span class="flex-1 break-words">{t.text}</span>
      <button class="opacity-60 hover:opacity-100" aria-label="Dismiss" onclick={() => dismissToast(t.id)}>✕</button>
    </div>
  {/each}
</div>
