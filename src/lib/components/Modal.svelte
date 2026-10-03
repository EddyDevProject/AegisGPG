<script lang="ts">
  import type { Snippet } from "svelte";
  import { fade, scale } from "svelte/transition";

  let {
    title,
    onclose,
    children,
    footer,
    wide = false,
  }: { title: string; onclose: () => void; children: Snippet; footer?: Snippet; wide?: boolean } = $props();

  let dialog = $state<HTMLDivElement>();

  $effect(() => {
    const prev = document.activeElement as HTMLElement | null;
    dialog?.querySelector<HTMLElement>("input,textarea,select,button")?.focus();
    return () => prev?.focus();
  });

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Escape") onclose();
    if (e.key === "Tab" && dialog) {
      const f = [...dialog.querySelectorAll<HTMLElement>("input,textarea,select,button:not([disabled])")];
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) (e.preventDefault(), last.focus());
      else if (!e.shiftKey && document.activeElement === last) (e.preventDefault(), first.focus());
    }
  }
</script>

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div
  class="fixed inset-0 z-40 flex items-center justify-center bg-black/40 p-4 backdrop-blur-sm"
  transition:fade={{ duration: 120 }}
  onclick={(e) => e.target === e.currentTarget && onclose()}
  {onkeydown}
>
  <div
    bind:this={dialog}
    role="dialog"
    aria-modal="true"
    aria-label={title}
    transition:scale={{ start: 0.97, duration: 140 }}
    class="max-h-full w-full overflow-auto rounded-xl border border-zinc-200 bg-white p-5 shadow-2xl dark:border-zinc-800 dark:bg-zinc-900 {wide ? 'max-w-2xl' : 'max-w-md'}"
  >
    <h3 class="mb-4 text-base font-semibold">{title}</h3>
    {@render children()}
    {#if footer}<div class="mt-5 flex justify-end gap-2">{@render footer()}</div>{/if}
  </div>
</div>
