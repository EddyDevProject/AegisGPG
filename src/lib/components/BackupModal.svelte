<script lang="ts">
  import { open, save } from "@tauri-apps/plugin-dialog";
  import Modal from "./Modal.svelte";
  import { api } from "../api";
  import { errorMessage, refreshKeys, toast } from "../stores.svelte";
  import { btn, input, label } from "../ui";

  let { onclose }: { onclose: () => void } = $props();

  /** Keep in sync with `MIN_PASSPHRASE_CHARS` in gpg/backup.rs. */
  const MIN = 10;

  let tab = $state<"backup" | "restore">("backup");
  let passphrase = $state("");
  let confirm = $state("");
  let busy = $state(false);

  const tooShort = $derived(passphrase.length < MIN);
  const mismatch = $derived(passphrase !== confirm);

  function switchTab(t: "backup" | "restore") {
    tab = t;
    passphrase = confirm = "";
  }

  async function backUp() {
    const day = new Date().toISOString().slice(0, 10);
    const path = await save({
      defaultPath: `aegisgpg-backup-${day}.asc`,
      filters: [{ name: "AegisGPG backup", extensions: ["asc"] }],
    });
    if (!path) return;
    busy = true;
    try {
      const r = await api.createBackup(path, passphrase);
      toast("success", `Backed up ${r.keys} keys (${r.secret_keys} with a secret key)`);
      onclose();
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }

  async function restore() {
    const path = await open({
      multiple: false,
      filters: [{ name: "AegisGPG backup", extensions: ["asc", "gpg", "pgp"] }],
    });
    if (typeof path !== "string") return;
    busy = true;
    try {
      const r = await api.restoreBackup(path, passphrase);
      await refreshKeys();
      toast("success", `Restored ${r.keys} keys (${r.secret_keys} with a secret key)`);
      onclose();
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Backup & restore" {onclose}>
  <div class="mb-4 inline-flex rounded-md border border-zinc-300 p-0.5 dark:border-zinc-700" role="tablist">
    {#each ["backup", "restore"] as const as t}
      <button
        role="tab"
        aria-selected={tab === t}
        class="rounded px-3 py-1 text-sm capitalize {tab === t ? 'bg-accent text-white' : 'text-zinc-600 dark:text-zinc-400'}"
        onclick={() => switchTab(t)}>{t === "backup" ? "Back up" : "Restore"}</button>
    {/each}
  </div>

  {#if tab === "backup"}
    <p class="mb-3 text-sm text-zinc-600 dark:text-zinc-400">
      Saves every key in your keyring, secret keys included, in one file encrypted with a passphrase you choose now. Anyone with the file and that passphrase can use your keys, so store it offline and never next to the passphrase.
    </p>
    <label class={label} for="bk-pass">Backup passphrase</label>
    <input id="bk-pass" type="password" class={input} autocomplete="off" placeholder="At least {MIN} characters" bind:value={passphrase} />
    <input type="password" class="{input} mt-2" autocomplete="off" placeholder="Repeat the passphrase" aria-label="Repeat the passphrase" bind:value={confirm} />
    {#if passphrase && tooShort}
      <p class="mt-2 text-sm text-amber-600 dark:text-amber-400">Use at least {MIN} characters.</p>
    {:else if confirm && mismatch}
      <p class="mt-2 text-sm text-red-600 dark:text-red-400" role="alert">The passphrases do not match.</p>
    {/if}
    <p class="mt-3 text-xs text-zinc-500">Contacts' trust levels are not included; keys, certifications and revocations are.</p>
  {:else}
    <p class="mb-3 text-sm text-zinc-600 dark:text-zinc-400">
      Choose a backup file made by AegisGPG and enter its passphrase. Keys you already have are merged, never removed.
    </p>
    <label class={label} for="bk-restore-pass">Backup passphrase</label>
    <input id="bk-restore-pass" type="password" class={input} autocomplete="off" bind:value={passphrase} />
  {/if}

  {#snippet footer()}
    <button class={btn.ghost} onclick={onclose}>Cancel</button>
    {#if tab === "backup"}
      <button class={btn.primary} disabled={busy || tooShort || mismatch} onclick={backUp}>Save backup…</button>
    {:else}
      <button class={btn.primary} disabled={busy || !passphrase} onclick={restore}>Choose file…</button>
    {/if}
  {/snippet}
</Modal>
