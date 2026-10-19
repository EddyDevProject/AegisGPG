<script lang="ts">
  import InfoTip from "../components/InfoTip.svelte";
  import { onMount } from "svelte";
  import { api } from "../api";
  import Avatar from "../components/Avatar.svelte";
  import TrustBadge from "../components/TrustBadge.svelte";
  import GenerateKeyModal from "../components/GenerateKeyModal.svelte";
  import ImportKeyModal from "../components/ImportKeyModal.svelte";
  import QrModal from "../components/QrModal.svelte";
  import ExportKeyModal from "../components/ExportKeyModal.svelte";
  import { askConfirm, errorMessage, fmtDate, keyLabel, keyring, prefs, refreshKeys, setAvatars, setRememberPassphrase, shortFp, toast, ui } from "../stores.svelte";
  import { btn, card } from "../ui";
  import type { KeyInfo } from "../types";

  let modal = $state<"generate" | "import" | null>(null);
  let exporting = $state<KeyInfo | null>(null);
  let qrFor = $state<KeyInfo | null>(null);

  const mine = $derived(keyring.list.filter((k) => k.has_secret));
  const others = $derived(keyring.list.filter((k) => !k.has_secret));

  onMount(refreshKeys);

  async function remove(k: KeyInfo) {
    const ok = await askConfirm(
      "Delete key?",
      `${keyLabel(k)} will be permanently removed from AegisGPG.${k.has_secret ? " This key includes a SECRET key: without a backup you will lose access to anything encrypted for it." : ""}`,
    );
    if (!ok) return;
    try {
      await api.deleteKey(k.fingerprint);
      await refreshKeys();
      toast("success", "Key deleted");
    } catch (e) {
      toast("error", errorMessage(e));
    }
  }
</script>

<div class="mb-4 flex items-center justify-between">
  <h2 class="flex items-center gap-2 text-lg font-semibold">Keys <InfoTip text="Your keyring: the keys stored in AegisGPG. Keys you own can decrypt and sign; other people's keys let you encrypt for them and verify their signatures." /></h2>
  <div class="flex gap-2">
    <label class="flex items-center gap-1.5 text-xs text-zinc-500" title="Sends a hash of each contact's email address to libravatar.org / gravatar.com">
      <input type="checkbox" checked={prefs.avatars} onchange={(e) => setAvatars(e.currentTarget.checked)} />
      Online avatars
    </label>
    <label class="flex items-center gap-1.5 text-xs text-zinc-500" title="Keeps a passphrase you typed in memory for 5 minutes, so you are not asked again. It is never written to disk.">
      <input type="checkbox" checked={prefs.rememberPassphrase} onchange={(e) => setRememberPassphrase(e.currentTarget.checked)} />
      Remember passphrase (5 min)
    </label>
    <button class={btn.outline} onclick={() => (modal = "import")}>Import</button>
    <button class={btn.primary} onclick={() => (modal = "generate")}>Generate key</button>
  </div>
</div>

{#snippet keyItem(k: KeyInfo)}
    <li class="{card} flex items-start justify-between gap-4 {ui.selected === k.fingerprint ? 'ring-2 ring-accent' : ''}">
      <button class="flex min-w-0 flex-1 items-start gap-3 text-left" onclick={() => (ui.selected = k.fingerprint)} aria-label="Open details for {k.name ?? k.email ?? 'key'}">
        <Avatar email={k.email} name={k.name} size={40} />
        <span class="min-w-0">
          <span class="flex flex-wrap items-center gap-2">
            <span class="truncate font-medium">{k.name ?? "Unnamed"}</span>
            {#if k.has_secret}<span class="rounded bg-accent/15 px-1.5 py-0.5 text-xs text-accent">Secret</span>{/if}
            {#if k.revoked}<span class="rounded bg-red-500/15 px-1.5 py-0.5 text-xs text-red-600 dark:text-red-400">Revoked</span>{:else if !k.has_secret}<TrustBadge level={k.validity} />{/if}
          </span>
          <span class="block truncate text-sm text-zinc-500">{k.email ?? ""}</span>
          <span class="mt-2 block font-mono text-xs text-zinc-500" title={k.fingerprint}>{shortFp(k.fingerprint)}</span>
          <span class="mt-1 block text-xs text-zinc-500">{k.algorithm} · Created {fmtDate(k.created)} · Expires {fmtDate(k.expires)}</span>
        </span>
      </button>
      <div class="flex shrink-0 gap-1">
        <button class={btn.ghost} aria-label="Show QR code" title="Show QR code" onclick={() => (qrFor = k)}>
          <svg viewBox="0 0 24 24" class="size-4" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h3v3h-3zM20 14v3M14 20h3M20 20v1"/></svg>
        </button>
        <button class={btn.ghost} onclick={() => (exporting = k)}>Export</button>
        <button class="{btn.ghost} text-red-600 dark:text-red-400" onclick={() => remove(k)}>Delete</button>
      </div>
    </li>
{/snippet}

{#if keyring.list.length === 0}
  <div class="{card} py-12 text-center text-sm text-zinc-500">
    {keyring.loading ? "Loading…" : "No keys yet. Generate a new key or import an existing one."}
  </div>
{:else}
  {#if mine.length}
    <h3 class="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-zinc-500">My keys <span class="font-normal">({mine.length})</span> <InfoTip text="Key pairs you generated or imported with their secret part. Only you can decrypt messages sent to them and sign with them. Back them up: if you lose the secret key, nothing encrypted for it can be recovered." /></h3>
    <ul class="mb-6 grid gap-3">
      {#each mine as k (k.fingerprint)}{@render keyItem(k)}{/each}
    </ul>
  {/if}
  {#if others.length}
    <h3 class="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-zinc-500">Contacts <span class="font-normal">({others.length})</span> <InfoTip text="Public keys of other people. Use them to encrypt files and messages for those people, or to check that something was really signed by them. They cannot be used to decrypt." /></h3>
    <ul class="grid gap-3">
      {#each others as k (k.fingerprint)}{@render keyItem(k)}{/each}
    </ul>
  {/if}
{/if}

{#if modal === "generate"}<GenerateKeyModal onclose={() => (modal = null)} />{/if}
{#if modal === "import"}<ImportKeyModal onclose={() => (modal = null)} />{/if}
{#if qrFor}<QrModal key={qrFor} onclose={() => (qrFor = null)} />{/if}
{#if exporting}<ExportKeyModal key={exporting} onclose={() => (exporting = null)} />{/if}
