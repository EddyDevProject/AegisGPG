<script lang="ts">
  import { save } from "@tauri-apps/plugin-dialog";
  import Modal from "./Modal.svelte";
  import { api } from "../api";
  import {
    copyText, errorMessage, groupFp, keyLabel, keyring, refreshKeys, toast, withPassphrase,
  } from "../stores.svelte";
  import { btn, input, label } from "../ui";
  import type { CertLevel, KeyInfo } from "../types";

  let { target, onclose }: { target: KeyInfo; onclose: () => void } = $props();

  const own = $derived(keyring.list.filter((k) => k.has_secret && !k.revoked && k.fingerprint !== target.fingerprint));
  let signer = $state("");
  let level = $state<CertLevel>("careful");
  // svelte-ignore state_referenced_locally (the modal is remounted per target)
  let selectedIds = $state<string[]>([...target.user_ids]);
  let verified = $state(false);
  let busy = $state(false);
  let done = $state(false);

  $effect(() => {
    if (!signer && own.length) signer = own[0].fingerprint;
  });

  const levels: { id: CertLevel; title: string; text: string }[] = [
    { id: "none", title: "No particular claim", text: "I make no statement about how well I verified this key." },
    { id: "casual", title: "Casual check", text: "I did some checking, e.g. confirmed the fingerprint over chat or mail." },
    { id: "careful", title: "Careful check", text: "I verified the fingerprint in person (or by a trusted channel) and checked a photo ID." },
  ];

  async function submit() {
    busy = true;
    try {
      const r = await withPassphrase(
        (passphrase) =>
          api.certifyKey({ target: target.fingerprint, signer, level, user_ids: selectedIds, passphrase }),
        "Unlock signing key",
        "Enter the passphrase of the key you are certifying with.",
      );
      if (r) {
        await refreshKeys();
        toast("success", "Key certified");
        done = true;
      }
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }

  async function exportSigned(toFile: boolean) {
    try {
      if (toFile) {
        const path = await save({
          defaultPath: `${target.key_id}-certified.asc`,
          filters: [{ name: "ASCII-armored key", extensions: ["asc"] }],
        });
        if (!path) return;
        await api.exportKeyToFile(target.fingerprint, false, path);
        toast("success", "Certified key saved");
      } else {
        await copyText(await api.exportKey(target.fingerprint, false), "Certified key copied");
      }
    } catch (e) {
      toast("error", errorMessage(e));
    }
  }
</script>

<Modal title={done ? "Key certified" : "Certify this key"} {onclose}>
  {#if done}
    <p class="text-sm text-zinc-600 dark:text-zinc-400">
      Your certification is stored on <strong>{keyLabel(target)}</strong>. To let them (or a keyserver) have it,
      send them the certified public key. Only share it with their consent.
    </p>
  {:else}
    <div class="mb-4 rounded-md border border-amber-500/40 bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-100">
      Compare this fingerprint with the owner over a channel you trust before signing:
      <div class="mt-1 font-mono text-xs break-all">{groupFp(target.fingerprint)}</div>
    </div>

    <div class="grid gap-4">
      <div>
        <label class={label} for="c-signer">Certify with</label>
        <select id="c-signer" class={input} bind:value={signer}>
          {#each own as k (k.fingerprint)}<option value={k.fingerprint}>{keyLabel(k)}</option>{/each}
        </select>
        {#if !own.length}<p class="mt-1 text-xs text-red-600 dark:text-red-400">You need a secret key of your own to certify.</p>{/if}
      </div>

      <fieldset class="grid gap-2">
        <legend class={label}>How well did you verify this person?</legend>
        {#each levels as l}
          <label class="flex cursor-pointer items-start gap-2 rounded-md border border-zinc-200 p-2 text-sm dark:border-zinc-800 {level === l.id ? 'border-accent bg-accent/5' : ''}">
            <input type="radio" name="lvl" class="mt-1" checked={level === l.id} onchange={() => (level = l.id)} />
            <span><span class="font-medium">{l.title}</span><br /><span class="text-xs text-zinc-500">{l.text}</span></span>
          </label>
        {/each}
      </fieldset>

      <fieldset>
        <legend class={label}>User IDs to certify</legend>
        {#each target.user_ids as uid}
          <label class="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={selectedIds.includes(uid)}
              onchange={() => (selectedIds = selectedIds.includes(uid) ? selectedIds.filter((x) => x !== uid) : [...selectedIds, uid])}
            />
            <span class="truncate">{uid}</span>
          </label>
        {/each}
      </fieldset>

      <label class="flex items-start gap-2 text-sm">
        <input type="checkbox" class="mt-1" bind:checked={verified} />
        I have verified that the fingerprint above belongs to this person.
      </label>
    </div>
  {/if}

  {#snippet footer()}
    {#if done}
      <button class={btn.ghost} onclick={onclose}>Close</button>
      <button class={btn.outline} onclick={() => exportSigned(true)}>Save to file…</button>
      <button class={btn.primary} onclick={() => exportSigned(false)}>Copy certified key</button>
    {:else}
      <button class={btn.ghost} onclick={onclose}>Cancel</button>
      <button class={btn.primary} disabled={busy || !verified || !signer || !selectedIds.length} onclick={submit}>
        {busy ? "Signing…" : "Certify"}
      </button>
    {/if}
  {/snippet}
</Modal>
