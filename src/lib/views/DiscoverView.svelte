<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "../api";
  import Avatar from "../components/Avatar.svelte";
  import { errorMessage, groupFp, keyLabel, keyring, refreshKeys, toast } from "../stores.svelte";
  import { btn, card, input, label } from "../ui";
  import type { RefreshReport, RemoteKey, ServerId, UploadReport } from "../types";

  type Source = "wkd" | ServerId;
  const serverNames: Record<ServerId, string> = {
    keys_openpgp_org: "keys.openpgp.org",
    keyserver_ubuntu_com: "keyserver.ubuntu.com",
  };

  onMount(refreshKeys);

  // ---- search
  let query = $state("");
  let source = $state<Source>("keys_openpgp_org");
  let searching = $state(false);
  let results = $state<RemoteKey[] | null>(null);
  let importing = $state<string | null>(null);

  async function search(e: Event) {
    e.preventDefault();
    searching = true;
    results = null;
    try {
      results = source === "wkd" ? await api.lookupWkd(query) : await api.lookupKeyserver(query, source);
    } catch (err) {
      toast("error", errorMessage(err));
    } finally {
      searching = false;
    }
  }

  async function importRemote(r: RemoteKey) {
    importing = r.info.fingerprint;
    try {
      await api.importKey(r.armored);
      await refreshKeys();
      r.already_have = true;
      toast("success", `Imported ${keyLabel(r.info)}`);
    } catch (err) {
      toast("error", errorMessage(err));
    } finally {
      importing = null;
    }
  }

  // ---- publish
  const own = $derived(keyring.list.filter((k) => k.has_secret));
  let publishKey = $state("");
  let publishServer = $state<ServerId>("keys_openpgp_org");
  let publishing = $state(false);
  let uploadReport = $state<UploadReport | null>(null);

  $effect(() => {
    if (!publishKey && own.length) publishKey = own[0].fingerprint;
  });

  async function publish() {
    publishing = true;
    uploadReport = null;
    try {
      uploadReport = await api.uploadKey(publishKey, publishServer);
      toast("success", "Public key sent");
    } catch (err) {
      toast("error", errorMessage(err));
    } finally {
      publishing = false;
    }
  }

  // ---- refresh
  let refreshServer = $state<ServerId>("keys_openpgp_org");
  let refreshing = $state(false);
  let report = $state<RefreshReport | null>(null);

  async function refresh() {
    refreshing = true;
    report = null;
    try {
      report = await api.refreshKeys(refreshServer);
      await refreshKeys();
      toast(report.changes.some((c) => c.change === "revoked") ? "error" : "success",
        report.changes.length ? `${report.changes.length} key(s) changed` : "Everything is up to date");
    } catch (err) {
      toast("error", errorMessage(err));
    } finally {
      refreshing = false;
    }
  }

  const statusText: Record<string, string> = {
    published: "Published",
    pending: "Check your inbox to confirm",
    unpublished: "Not published (needs verification)",
    revoked: "Revoked",
  };
</script>

<h2 class="mb-4 text-lg font-semibold">Discover &amp; Sync</h2>

<div class="grid max-w-3xl gap-5">
  <section class="{card} grid gap-3" aria-labelledby="find">
    <h3 id="find" class="text-sm font-semibold">Find a key</h3>
    <form class="grid gap-3 sm:grid-cols-[1fr_auto_auto]" onsubmit={search}>
      <input
        class={input}
        aria-label="Email address or fingerprint"
        placeholder={source === "wkd" ? "user@domain.com" : "Email, fingerprint or key ID"}
        bind:value={query}
      />
      <select class={input} aria-label="Source" bind:value={source}>
        <option value="keys_openpgp_org">keys.openpgp.org</option>
        <option value="wkd">Web Key Directory (email)</option>
        <option value="keyserver_ubuntu_com">keyserver.ubuntu.com</option>
      </select>
      <button class={btn.primary} disabled={searching || !query.trim()}>{searching ? "Searching…" : "Search"}</button>
    </form>

    {#if source === "wkd"}
      <p class="text-xs text-zinc-500">Queries the key published by the email's own domain (advanced, then direct method). The key must contain that address.</p>
    {:else if source === "keyserver_ubuntu_com"}
      <p class="text-xs text-amber-600 dark:text-amber-400">This server does not verify email ownership. Always compare the fingerprint with the owner.</p>
    {/if}

    {#if results}
      <ul class="grid gap-2">
        {#each results as r (r.info.fingerprint)}
          <li class="flex items-center gap-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
            <Avatar email={r.info.email} name={r.info.name} />
            <div class="min-w-0 flex-1">
              <div class="truncate text-sm font-medium">{keyLabel(r.info)}</div>
              <div class="font-mono text-xs break-all text-zinc-500">{groupFp(r.info.fingerprint)}</div>
              {#if r.info.revoked}<div class="text-xs text-red-600 dark:text-red-400">This key is revoked</div>{/if}
            </div>
            {#if r.already_have}
              <span class="text-xs text-zinc-500">In keyring</span>
            {:else}
              <button class={btn.primary} disabled={importing === r.info.fingerprint} onclick={() => importRemote(r)}>Import</button>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section class="{card} grid gap-3" aria-labelledby="pub">
    <h3 id="pub" class="text-sm font-semibold">Publish my public key</h3>
    {#if !own.length}
      <p class="text-sm text-zinc-500">Generate a key of your own first.</p>
    {:else}
      <div class="grid gap-3 sm:grid-cols-[1fr_auto_auto]">
        <select class={input} aria-label="Key to publish" bind:value={publishKey}>
          {#each own as k (k.fingerprint)}<option value={k.fingerprint}>{keyLabel(k)}</option>{/each}
        </select>
        <select class={input} aria-label="Keyserver" bind:value={publishServer}>
          {#each Object.entries(serverNames) as [id, n]}<option value={id}>{n}</option>{/each}
        </select>
        <button class={btn.primary} disabled={publishing} onclick={publish}>{publishing ? "Sending…" : "Publish"}</button>
      </div>
      <p class="text-xs text-zinc-500">Only the public key is sent. Keyservers may keep it permanently: deleting it later is not guaranteed.</p>
    {/if}
    {#if uploadReport}
      <ul class="grid gap-1 text-sm">
        {#each uploadReport.emails as e}
          <li><span class="font-medium">{e.email}</span>: {statusText[e.status] ?? e.status}</li>
        {:else}
          <li class="text-zinc-500">Submitted. This server does not report verification status.</li>
        {/each}
      </ul>
      {#if uploadReport.verification_requested}
        <p class="text-xs text-zinc-500">A verification email was requested. Open the link in it to make the address searchable.</p>
      {/if}
    {/if}
  </section>

  <section class="{card} grid gap-3" aria-labelledby="sync">
    <h3 id="sync" class="text-sm font-semibold">Update keys &amp; check revocations</h3>
    <div class="grid gap-3 sm:grid-cols-[1fr_auto]">
      <div>
        <label class={label} for="rs">Keyserver</label>
        <select id="rs" class={input} bind:value={refreshServer}>
          {#each Object.entries(serverNames) as [id, n]}<option value={id}>{n}</option>{/each}
        </select>
      </div>
      <button class="{btn.primary} self-end" disabled={refreshing || !keyring.list.length} onclick={refresh}>
        {refreshing ? "Checking…" : "Check all keys"}
      </button>
    </div>
    {#if report}
      <p class="text-sm text-zinc-500">
        Checked {report.checked} · unchanged {report.unchanged} · not on server {report.not_found}
      </p>
      <ul class="grid gap-1 text-sm">
        {#each report.changes as c}
          <li class={c.change === "revoked" ? "font-medium text-red-600 dark:text-red-400" : ""}>
            {c.label}: {c.change === "revoked" ? "REVOKED" : "updated"}
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>
