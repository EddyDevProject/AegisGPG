<script lang="ts">
  import { onMount } from "svelte";
  import { keyLabel, keyring, refreshTeams, shortFp, teamStore, toast } from "../stores.svelte";
  import { card } from "../ui";

  let { selected = $bindable([]) }: { selected: string[] } = $props();

  let openList = $state(false);
  const usable = $derived(keyring.list.filter((k) => !k.revoked));

  onMount(refreshTeams);

  /** Usable members of a team: key present in the keyring and not revoked. */
  const teamKeys = (members: string[]) => members.filter((fp) => usable.some((k) => k.fingerprint === fp));

  function toggleTeam(members: string[]) {
    const ok = teamKeys(members);
    if (!ok.length) return toast("error", "None of this team's keys are available");
    if (ok.every((fp) => selected.includes(fp))) {
      selected = selected.filter((fp) => !ok.includes(fp));
      return;
    }
    selected = [...new Set([...selected, ...ok])];
    if (ok.length < members.length) toast("info", `${members.length - ok.length} team member(s) skipped: key missing or revoked`);
  }

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
      {#if teamStore.list.length}
        <li role="presentation" class="px-2 pt-1 pb-0.5 text-xs font-medium text-zinc-500">Teams</li>
        {#each teamStore.list as t (t.id)}
          {@const ok = teamKeys(t.members)}
          {@const all = ok.length > 0 && ok.every((fp) => selected.includes(fp))}
          <li role="presentation">
            <button
              type="button"
              class="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-zinc-100 dark:hover:bg-zinc-800"
              onclick={() => toggleTeam(t.members)}
            >
              <span aria-hidden="true">👥</span>
              <span class="flex-1 truncate">{t.name}</span>
              <span class="text-xs text-zinc-500">{all ? "✓ " : ""}{ok.length}/{t.members.length}</span>
            </button>
          </li>
        {/each}
        <li role="presentation" class="mx-2 my-1 border-t border-zinc-200 dark:border-zinc-800"></li>
      {/if}
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
