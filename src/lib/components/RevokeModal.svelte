<script lang="ts">
  import { save } from "@tauri-apps/plugin-dialog";
  import Modal from "./Modal.svelte";
  import { api } from "../api";
  import { askConfirm, errorMessage, keyLabel, refreshKeys, toast, withPassphrase } from "../stores.svelte";
  import { btn, input, label } from "../ui";
  import type { KeyInfo, RevokeReason } from "../types";

  let { key, onclose }: { key: KeyInfo; onclose: () => void } = $props();

  let reason = $state<RevokeReason>("compromised");
  let message = $state("");
  let busy = $state(false);

  const reasons: { id: RevokeReason; label: string }[] = [
    { id: "compromised", label: "The key was lost, stolen or exposed" },
    { id: "superseded", label: "I replaced it with a new key" },
    { id: "retired", label: "I no longer use it" },
    { id: "unspecified", label: "Other" },
  ];

  const request = (passphrase?: string) => ({ fingerprint: key.fingerprint, reason, message: message.trim() || undefined, passphrase });
  const unlock = ["Unlock secret key", "Your passphrase is needed to sign the revocation."] as const;

  async function saveCertificate() {
    const path = await save({
      defaultPath: `${key.key_id}-revocation.asc`,
      filters: [{ name: "ASCII-armored key", extensions: ["asc"] }],
    });
    if (!path) return;
    busy = true;
    try {
      const done = await withPassphrase((p) => api.saveRevocationCertificate(request(p), path).then(() => true), ...unlock);
      if (done) {
        toast("success", "Revocation certificate saved. Keep it somewhere safe and separate from your key.");
        onclose();
      }
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }

  async function revokeNow() {
    const ok = await askConfirm(
      "Revoke this key?",
      `${keyLabel(key)} will be marked as revoked. This cannot be undone: you will no longer be able to sign or be sent new messages with it. Publish the revocation afterwards so others find out.`,
      "Revoke",
    );
    if (!ok) return;
    busy = true;
    try {
      const done = await withPassphrase((p) => api.revokeKey(request(p)), ...unlock);
      if (done) {
        await refreshKeys();
        toast("success", "Key revoked. Publish it from Discover & Sync so others learn of it.");
        onclose();
      }
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Revoke key" {onclose}>
  <p class="mb-3 truncate text-sm text-zinc-500">{keyLabel(key)}</p>
  <p class="mb-4 text-sm text-zinc-600 dark:text-zinc-400">
    A revocation certificate tells everyone that this key must no longer be trusted. Save one now and keep it away from your key: if you ever lose the key or its passphrase, it is the only way to retire it.
  </p>
  <label class={label} for="rv-reason">Reason</label>
  <select id="rv-reason" class={input} bind:value={reason}>
    {#each reasons as r (r.id)}<option value={r.id}>{r.label}</option>{/each}
  </select>
  <label class="{label} mt-3" for="rv-msg">Note (optional)</label>
  <input id="rv-msg" class={input} placeholder="Shown to people who import the revocation" bind:value={message} />
  {#snippet footer()}
    <button class={btn.ghost} onclick={onclose}>Cancel</button>
    <button class={btn.primary} disabled={busy} onclick={saveCertificate}>Save certificate…</button>
    <button class={btn.danger} disabled={busy} onclick={revokeNow}>Revoke now</button>
  {/snippet}
</Modal>
