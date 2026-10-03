<script lang="ts">
  import { keyLabel, keyring, shortFp } from "../stores.svelte";
  import { card } from "../ui";

  let { selected = $bindable([]) }: { selected: string[] } = $props();

  let openList = $state(false);
  const usable = $derived(keyring.list.filter((k) => !k.revoked));

  function toggle(fp: string) {
    selected = selected.includes(fp) ? selected.filter((f) => f !== fp) : [...selected, fp];
  }
</script>

<div class="relative">
  <button
    type="button"
    class="flex w-full items-center justify-between rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-left text-sm dark:border-zinc-700 dark:bg-zinc-900"
    aria-haspopup="listbox"
    aria-expanded={openList}
    onclick={() => (openList = !openList)}
  >
    <span class={selected.length ? "" : "text-zinc-400"}>
      {selected.length ? `${selected.length} recipient${selected.length > 1 ? "s" : ""} selected` : "Select recipients…"}
    </span>
    <span aria-hidden="true">▾</span>
  </button>

  {#if openList}
    <ul
      role="listbox"
      aria-multiselectable="true"
      class="{card} absolute z-20 mt-1 max-h-60 w-full overflow-auto p-1 shadow-xl"
    >
      {#each usable as k (k.fingerprint)}
        <li role="option" aria-selected={selected.includes(k.fingerprint)}>
          <label class="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-zinc-100 dark:hover:bg-zinc-800">
            <input type="checkbox" checked={selected.includes(k.fingerprint)} onchange={() => toggle(k.fingerprint)} />
            <span class="flex-1 truncate">{keyLabel(k)}</span>
            <span class="font-mono text-xs text-zinc-500">{shortFp(k.fingerprint).slice(-9)}</span>
          </label>
        </li>
      {:else}
        <li class="px-2 py-3 text-sm text-zinc-500">No keys yet. Import or generate one in the Keys tab.</li>
      {/each}
    </ul>
  {/if}
</div>
