<script lang="ts">
  import { fly } from "svelte/transition";
  import { api } from "../api";
  import Avatar from "./Avatar.svelte";
  import CertifyModal from "./CertifyModal.svelte";
  import QrModal from "./QrModal.svelte";
  import ExportKeyModal from "./ExportKeyModal.svelte";
  import TrustBadge from "./TrustBadge.svelte";
  import {
    copyText, errorMessage, fmtDate, groupFp, keyring, refreshKeys, toast, trustLabels, trustLevels, ui,
  } from "../stores.svelte";
  import { btn, input, label } from "../ui";
  import type { KeyDetail, Trust } from "../types";

  let detail = $state<KeyDetail | null>(null);
  let certifying = $state(false);
  let exporting = $state(false);
  let showQr = $state(false);

  // Reload whenever the selection or the keyring (e.g. after certifying) changes.
  $effect(() => {
    const fp = ui.selected;
    void keyring.list;
    if (!fp) {
      detail = null;
      return;
    }
    api.keyDetail(fp).then(
      (d) => fp === ui.selected && (detail = d),
      (e) => {
        toast("error", errorMessage(e));
        ui.selected = null;
      },
    );
  });

  const k = $derived(detail?.info);
  const canCertify = $derived(!!k && !k.has_secret && keyring.list.some((o) => o.has_secret && !o.revoked));

  async function setTrust(level: Trust) {
    if (!k) return;
    try {
      await api.setOwnertrust(k.fingerprint, level);
      await refreshKeys();
    } catch (e) {
      toast("error", errorMessage(e));
    }
  }

  const purposeLabel = { certify: "Certify", sign: "Sign", encrypt: "Encrypt", authenticate: "Authenticate" };
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && !certifying && !exporting && !showQr && (ui.selected = null)} />

{#if k && detail}
  <aside
    transition:fly={{ x: 400, duration: 180 }}
    class="fixed inset-y-0 right-0 z-30 flex w-[26rem] max-w-full flex-col border-l border-zinc-200 bg-white shadow-2xl dark:border-zinc-800 dark:bg-zinc-900"
    aria-label="Contact details"
  >
    <header class="flex items-start gap-3 border-b border-zinc-200 p-4 dark:border-zinc-800">
      <Avatar email={k.email} name={k.name} size={48} />
      <div class="min-w-0 flex-1">
        <h3 class="truncate font-semibold">{k.name ?? "Unnamed"}</h3>
        {#if k.comment}<p class="truncate text-sm text-zinc-500">{k.comment}</p>{/if}
        <p class="truncate text-sm text-zinc-500">{k.email ?? "No email"}</p>
        <div class="mt-1.5 flex flex-wrap gap-1">
          {#if k.has_secret}<span class="rounded bg-accent/15 px-1.5 py-0.5 text-xs text-accent">Your key</span>{/if}
          <TrustBadge level={k.validity} prefix="Validity: " />
          {#if k.revoked}<span class="rounded bg-red-500/15 px-1.5 py-0.5 text-xs text-red-600 dark:text-red-400">Revoked</span>{/if}
        </div>
      </div>
      <button class={btn.ghost} aria-label="Close" onclick={() => (ui.selected = null)}>✕</button>
    </header>

    <div class="flex-1 space-y-5 overflow-auto p-4 text-sm">
      <section>
        <div class={label}>Fingerprint</div>
        <div class="flex items-start gap-2">
          <code class="flex-1 font-mono text-xs leading-relaxed break-all">{groupFp(k.fingerprint)}</code>
          <button class={btn.outline} onclick={() => copyText(k.fingerprint, "Fingerprint copied")}>Copy</button>
        </div>
        <div class="mt-2 grid grid-cols-2 gap-2">
          <div class="flex items-center justify-between gap-2 rounded-md border border-zinc-200 px-2 py-1 dark:border-zinc-800">
            <span><span class="block text-[10px] text-zinc-500">Long ID</span><code class="font-mono text-xs">{k.key_id}</code></span>
            <button class="text-xs text-accent" onclick={() => copyText(k.key_id, "Key ID copied")}>Copy</button>
          </div>
          <div class="flex items-center justify-between gap-2 rounded-md border border-zinc-200 px-2 py-1 dark:border-zinc-800">
            <span><span class="block text-[10px] text-zinc-500">Short ID</span><code class="font-mono text-xs">{k.key_id.slice(-8)}</code></span>
            <button class="text-xs text-accent" onclick={() => copyText(k.key_id.slice(-8), "Short ID copied")}>Copy</button>
          </div>
        </div>
      </section>

      <section>
        <label class={label} for="ownertrust">Trust in this person to certify others (ownertrust)</label>
        <select id="ownertrust" class={input} value={k.ownertrust} onchange={(e) => setTrust(e.currentTarget.value as Trust)}>
          {#each trustLevels as t}<option value={t}>{trustLabels[t]}</option>{/each}
        </select>
      </section>

      <section>
        <div class={label}>User IDs</div>
        <ul class="space-y-0.5">{#each k.user_ids as u}<li class="break-words">{u}</li>{/each}</ul>
      </section>

      <section>
        <div class={label}>Keys &amp; subkeys</div>
        <ul class="space-y-2">
          {#each detail.subkeys as s (s.fingerprint)}
            <li class="rounded-md border border-zinc-200 p-2 dark:border-zinc-800">
              <div class="flex items-center justify-between">
                <span class="font-medium">{s.is_primary ? "Primary key" : "Subkey"} · {s.algorithm}</span>
                {#if s.revoked}<span class="text-xs text-red-600 dark:text-red-400">Revoked</span>{/if}
              </div>
              <div class="mt-1 flex flex-wrap gap-1">
                {#each s.purposes as p}<span class="rounded bg-zinc-500/15 px-1.5 py-0.5 text-xs">{purposeLabel[p]}</span>{/each}
              </div>
              <div class="mt-1 font-mono text-xs text-zinc-500">{s.key_id}</div>
              <div class="text-xs text-zinc-500">Created {fmtDate(s.created)} · Expires {fmtDate(s.expires)}</div>
            </li>
          {/each}
        </ul>
      </section>
    </div>

    <footer class="flex gap-2 border-t border-zinc-200 p-3 dark:border-zinc-800">
      <button class={btn.outline} aria-label="Show QR code" title="Show QR code" onclick={() => (showQr = true)}>
        <svg viewBox="0 0 24 24" class="size-4" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h3v3h-3zM20 14v3M14 20h3M20 20v1"/></svg>
        QR
      </button>
      <button class={btn.outline} onclick={() => (exporting = true)}>Export</button>
      <button
        class="{btn.primary} flex-1"
        disabled={!canCertify}
        title={k.has_secret ? "This is your own key" : canCertify ? "" : "Generate a key of your own first"}
        onclick={() => (certifying = true)}
      >
        Certify this key
      </button>
    </footer>
  </aside>

  {#if certifying}<CertifyModal target={k} onclose={() => (certifying = false)} />{/if}
  {#if showQr}<QrModal key={k} onclose={() => (showQr = false)} />{/if}
  {#if exporting}<ExportKeyModal key={k} onclose={() => (exporting = false)} />{/if}
{/if}
