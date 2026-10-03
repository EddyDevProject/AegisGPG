<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "../api";
  import TeamModal from "../components/TeamModal.svelte";
  import { askConfirm, errorMessage, keyLabel, keyring, refreshKeys, refreshTeams, shortFp, teamStore, toast } from "../stores.svelte";
  import { btn, card } from "../ui";
  import type { Team } from "../types";

  let editing = $state<Team | null>(null);
  let creating = $state(false);

  onMount(() => {
    refreshKeys();
    refreshTeams();
  });

  const byFp = $derived(new Map(keyring.list.map((k) => [k.fingerprint, k])));

  async function remove(t: Team) {
    const ok = await askConfirm("Delete team?", `"${t.name}" will be removed. The keys of its members are not affected.`);
    if (!ok) return;
    try {
      await api.deleteTeam(t.id);
      await refreshTeams();
      toast("success", "Team deleted");
    } catch (e) {
      toast("error", errorMessage(e));
    }
  }
</script>

<div class="mb-4 flex items-center justify-between">
  <h2 class="text-lg font-semibold">Teams</h2>
  <button class={btn.primary} onclick={() => (creating = true)}>New team</button>
</div>

<p class="mb-4 max-w-2xl text-sm text-zinc-500">
  A team is a named group of keys. Pick it in <em>Encrypt &amp; Sign</em> or <em>Quick Text</em> to encrypt for all of its members at once.
  Teams are stored only on this device.
</p>

<div class="grid max-w-2xl gap-3">
  {#each teamStore.list as t (t.id)}
    <section class={card} aria-label={t.name}>
      <div class="flex items-center justify-between gap-2">
        <h3 class="font-medium">{t.name} <span class="text-xs font-normal text-zinc-500">· {t.members.length} member{t.members.length === 1 ? "" : "s"}</span></h3>
        <div class="flex gap-1">
          <button class={btn.ghost} onclick={() => (editing = t)}>Edit</button>
          <button class={btn.ghost} onclick={() => remove(t)}>Delete</button>
        </div>
      </div>
      <ul class="mt-2 grid gap-1 text-sm">
        {#each t.members as fp (fp)}
          {@const k = byFp.get(fp)}
          <li class="flex items-center gap-2">
            {#if !k}
              <span class="flex-1 text-amber-600 dark:text-amber-400">Key no longer in keyring</span>
            {:else}
              <span class="flex-1 truncate">{keyLabel(k)}</span>
              {#if k.revoked}<span class="text-xs text-amber-600 dark:text-amber-400">revoked, will be skipped</span>{/if}
            {/if}
            <span class="font-mono text-xs text-zinc-500">{shortFp(fp).slice(-9)}</span>
          </li>
        {:else}
          <li class="text-zinc-500">No members yet.</li>
        {/each}
      </ul>
    </section>
  {:else}
    <p class="text-sm text-zinc-500">No teams yet.</p>
  {/each}
</div>

{#if creating}<TeamModal team={null} onclose={() => (creating = false)} />{/if}
{#if editing}<TeamModal team={editing} onclose={() => (editing = null)} />{/if}
