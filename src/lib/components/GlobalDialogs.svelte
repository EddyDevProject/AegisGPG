<script lang="ts">
  import Modal from "./Modal.svelte";
  import { api } from "../api";
  import {
    confirmPrompt, errorMessage, passphrasePrompt, refreshKleyKnox, setKleyKnoxTtl, kleyknox, kleyknoxTtl, kleyknoxTtls, toast,
  } from "../stores.svelte";
  import { btn, input, label } from "../ui";

  let value = $state("");
  /** Which form the passphrase dialog shows: the key's own passphrase or KleyKnox's. */
  let mode = $state<"key" | "kleyknox">("key");
  let ttl = $state(kleyknoxTtl());
  let busy = $state(false);
  let kleyknoxError = $state("");

  // Each time the dialog opens, start on the form the caller asked for.
  $effect(() => {
    if (passphrasePrompt.open) {
      mode = passphrasePrompt.kleyknox ? "kleyknox" : "key";
      kleyknoxError = "";
      void refreshKleyKnox();
    }
  });

  function closePass(v: string | null) {
    passphrasePrompt.resolve?.(v);
    passphrasePrompt.open = false;
    value = "";
  }
  function closeConfirm(v: boolean) {
    confirmPrompt.resolve?.(v);
    confirmPrompt.open = false;
  }

  async function unlockKleyKnox() {
    busy = true;
    kleyknoxError = "";
    try {
      const r = await api.kleyknoxUnlock(value, ttl);
      setKleyKnoxTtl(ttl);
      if (r.imported.length) toast("info", `Imported from KleyKnox: ${r.imported.join(", ")}`);
      if (r.mismatched.length) {
        toast("error", `KleyKnox's passphrase does not open your copy of: ${r.mismatched.join(", ")}`, 8000);
      }
      if (!r.unlocked.length) {
        kleyknoxError = "KleyKnox holds none of the keys needed here.";
        return;
      }
      const span = kleyknoxTtls.find((t) => t.seconds === ttl)?.label ?? "a while";
      toast("success", `Unlocked with KleyKnox for ${span}: ${r.unlocked.join(", ")}`);
      closePass("");
    } catch (e) {
      kleyknoxError = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

{#if passphrasePrompt.open}
  <Modal title={passphrasePrompt.title} onclose={() => closePass(null)}>
    <form
      id="pp"
      onsubmit={(e) => {
        e.preventDefault();
        if (mode === "kleyknox") void unlockKleyKnox();
        else closePass(value);
      }}
    >
      {#if mode === "key"}
        {#if passphrasePrompt.description}
          <p class="mb-3 text-sm text-zinc-500">{passphrasePrompt.description}</p>
        {/if}
        <input type="password" class={input} placeholder="Passphrase" autocomplete="off" bind:value />
        {#if passphrasePrompt.error}
          <p class="mt-2 text-sm text-red-600 dark:text-red-400" role="alert">{passphrasePrompt.error}</p>
        {/if}
        {#if kleyknox.dir}
          <button type="button" class="mt-3 text-xs text-knox-ink hover:underline dark:text-knox" onclick={() => ((mode = "kleyknox"), (value = ""))}>
            Unlock with KleyKnox instead
          </button>
        {/if}
      {:else}
        <p class="mb-3 text-sm text-zinc-500">
          Your KleyKnox passphrase unlocks every key on the stick for the time you choose. Nothing is written to disk.
        </p>
        {#if kleyknox.dir}
          <p class="mb-3 truncate font-mono text-xs text-zinc-400" title={kleyknox.dir}>{kleyknox.dir}</p>
        {:else}
          <p class="mb-3 text-sm text-amber-600 dark:text-amber-400">Plug in the KleyKnox stick first.</p>
        {/if}
        <input type="password" class={input} placeholder="KleyKnox passphrase" autocomplete="off" disabled={busy} bind:value />
        <label class="{label} mt-3" for="pp-ttl">Keep unlocked for</label>
        <select id="pp-ttl" class={input} disabled={busy} bind:value={ttl}>
          {#each kleyknoxTtls as t}<option value={t.seconds}>{t.label}</option>{/each}
        </select>
        {#if kleyknoxError}
          <p class="mt-2 text-sm text-red-600 dark:text-red-400" role="alert">{kleyknoxError}</p>
        {/if}
        {#if !passphrasePrompt.kleyknoxOnly}
          <button type="button" class="mt-3 text-xs text-accent hover:underline" onclick={() => ((mode = "key"), (value = ""))}>
            Use the key's own passphrase instead
          </button>
        {/if}
      {/if}
    </form>
    {#snippet footer()}
      <button class={btn.ghost} onclick={() => closePass(null)}>Cancel</button>
      <button
        class={mode === "kleyknox" ? btn.knox : btn.primary}
        type="submit"
        form="pp"
        disabled={!value || busy || (mode === "kleyknox" && !kleyknox.dir)}
      >
        {busy ? "Unlocking…" : "Unlock"}
      </button>
    {/snippet}
  </Modal>
{/if}

{#if confirmPrompt.open}
  <Modal title={confirmPrompt.title} onclose={() => closeConfirm(false)}>
    <p class="text-sm text-zinc-600 dark:text-zinc-400">{confirmPrompt.description}</p>
    {#snippet footer()}
      <button class={btn.ghost} onclick={() => closeConfirm(false)}>Cancel</button>
      <button class={btn.danger} onclick={() => closeConfirm(true)}>{confirmPrompt.confirmLabel}</button>
    {/snippet}
  </Modal>
{/if}
