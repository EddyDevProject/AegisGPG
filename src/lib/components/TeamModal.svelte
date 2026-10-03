<script lang="ts">
  import Modal from "./Modal.svelte";
  import { api } from "../api";
  import { errorMessage, keyLabel, keyring, refreshTeams, shortFp, toast } from "../stores.svelte";
  import { btn, input, label } from "../ui";
  import type { Team } from "../types";

  let { team, onclose }: { team: Team | null; onclose: () => void } = $props();

  // svelte-ignore state_referenced_locally
  let name = $state(team?.name ?? "");
  // svelte-ignore state_referenced_locally
  let members = $state<string[]>(team?.members ?? []);
  let busy = $state(false);

  const usable = $derived(keyring.list.filter((k) => !k.revoked));
  const known = $derived(new Set(keyring.list.map((k) => k.fingerprint)));
  // Members whose key was deleted stay listed so they can be removed explicitly.
  const orphans = $derived(members.filter((fp) => !known.has(fp)));

  function toggle(fp: string) {
    members = members.includes(fp) ? members.filter((f) => f !== fp) : [...members, fp];
  }

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    try {
      await api.saveTeam(name, members, team?.id);
      await refreshTeams();
      toast("success", team ? "Team updated" : "Team created");
      onclose();
    } catch (err) {
      toast("error", errorMessage(err));
    } finally {
      busy = false;
    }
  }
</script>

<Modal title={team ? "Edit team" : "New team"} {onclose}>
  <form id="team" class="grid gap-3" onsubmit={submit}>
    <div><label class={label} for="t-name">Team name</label><input id="t-name" class={input} bind:value={name} required /></div>
    <fieldset>
      <legend class={label}>Members ({members.length})</legend>
      <ul class="max-h-60 overflow-auto rounded-md border border-zinc-200 p-1 dark:border-zinc-800">
        {#each usable as k (k.fingerprint)}
          <li>
            <label class="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-zinc-100 dark:hover:bg-zinc-800">
              <input type="checkbox" checked={members.includes(k.fingerprint)} onchange={() => toggle(k.fingerprint)} />
              <span class="flex-1 truncate">{keyLabel(k)}</span>
              <span class="font-mono text-xs text-zinc-500">{shortFp(k.fingerprint).slice(-9)}</span>
            </label>
          </li>
        {:else}
          <li class="px-2 py-3 text-sm text-zinc-500">No keys yet. Import or generate one in the Keys tab.</li>
        {/each}
        {#each orphans as fp (fp)}
          <li>
            <label class="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm text-amber-600 hover:bg-zinc-100 dark:text-amber-400 dark:hover:bg-zinc-800">
              <input type="checkbox" checked onchange={() => toggle(fp)} />
              <span class="flex-1">Key no longer in keyring</span>
              <span class="font-mono text-xs">{shortFp(fp).slice(-9)}</span>
            </label>
          </li>
        {/each}
      </ul>
    </fieldset>
  </form>
  {#snippet footer()}
    <button type="button" class={btn.ghost} onclick={onclose}>Cancel</button>
    <button class={btn.primary} form="team" disabled={busy || !name.trim()}>{busy ? "Saving…" : "Save"}</button>
  {/snippet}
</Modal>
