<script lang="ts">
  import { getCurrentWebview } from "@tauri-apps/api/webview";
  import { open } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";

  let {
    onfile,
    path = null,
    label = "Drop a file here, or click to browse",
    extensions,
  }: {
    onfile: (path: string) => void;
    path?: string | null;
    label?: string;
    extensions?: string[];
  } = $props();

  let over = $state(false);

  onMount(() => {
    const un = getCurrentWebview().onDragDropEvent((e) => {
      const p = e.payload;
      if (p.type === "enter" || p.type === "over") over = true;
      else if (p.type === "leave") over = false;
      else if (p.type === "drop") {
        over = false;
        if (p.paths[0]) onfile(p.paths[0]);
      }
    });
    return () => void un.then((f) => f());
  });

  async function browse() {
    const sel = await open({
      multiple: false,
      directory: false,
      filters: extensions ? [{ name: "Files", extensions }, { name: "All files", extensions: ["*"] }] : undefined,
    });
    if (typeof sel === "string") onfile(sel);
  }

  const name = (p: string) => p.split(/[\\/]/).pop();
</script>

<button
  type="button"
  onclick={browse}
  class="flex w-full flex-col items-center justify-center gap-1 rounded-xl border-2 border-dashed px-4 py-10 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-accent
    {over ? 'border-accent bg-accent/10' : 'border-zinc-300 hover:border-zinc-400 dark:border-zinc-700 dark:hover:border-zinc-600'}"
>
  {#if path}
    <span class="font-medium">{name(path)}</span>
    <span class="max-w-full truncate text-xs text-zinc-500">{path}</span>
  {:else}
    <span class="text-2xl" aria-hidden="true">⬆</span>
    <span class="text-zinc-500">{label}</span>
  {/if}
</button>
