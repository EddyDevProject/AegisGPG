<script lang="ts">
  import { save } from "@tauri-apps/plugin-dialog";
  import Modal from "./Modal.svelte";
  import { api } from "../api";
  import { errorMessage, keyLabel, toast } from "../stores.svelte";
  import { btn, input } from "../ui";
  import type { KeyInfo } from "../types";

  let { key, onclose }: { key: KeyInfo; onclose: () => void } = $props();

  let secret = $state(false);
  let passphrase = $state("");
  let busy = $state(false);

  const needsPass = $derived(secret && key.secret_encrypted);
  const pass = () => (needsPass ? passphrase : undefined);

  async function toClipboard() {
    busy = true;
    try {
      const armored = await api.exportKey(key.fingerprint, secret, pass());
      await navigator.clipboard.writeText(armored);
      toast("success", `${secret ? "Secret" : "Public"} key copied to clipboard`);
      onclose();
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }

  async function toFile() {
    const path = await save({
      defaultPath: `${key.key_id}${secret ? "-secret" : ""}.asc`,
      filters: [{ name: "ASCII-armored key", extensions: ["asc"] }],
    });
    if (!path) return;
    busy = true;
    try {
      await api.exportKeyToFile(key.fingerprint, secret, path, pass());
      toast("success", "Key saved");
      onclose();
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Export key" {onclose}>
  <p class="mb-3 truncate text-sm text-zinc-500">{keyLabel(key)}</p>
  <label class="flex items-center gap-2 text-sm" class:opacity-50={!key.has_secret}>
    <input type="checkbox" bind:checked={secret} disabled={!key.has_secret} />
    Export secret key (keep it private!)
  </label>
  {#if needsPass}
    <input type="password" class="{input} mt-3" placeholder="Key passphrase" aria-label="Key passphrase" bind:value={passphrase} />
  {/if}
  {#snippet footer()}
    <button class={btn.ghost} onclick={onclose}>Cancel</button>
    <button class={btn.outline} disabled={busy || (needsPass && !passphrase)} onclick={toFile}>Save to file…</button>
    <button class={btn.primary} disabled={busy || (needsPass && !passphrase)} onclick={toClipboard}>Copy</button>
  {/snippet}
</Modal>
