<script lang="ts">
  import { onMount } from "svelte";
  import { save } from "@tauri-apps/plugin-dialog";
  import { api, onProgress } from "../api";
  import FileDropzone from "../components/FileDropzone.svelte";
  import ProgressBar from "../components/ProgressBar.svelte";
  import RecipientSelect from "../components/RecipientSelect.svelte";
  import { errorMessage, keyLabel, keyring, refreshKeys, toast, withPassphrase } from "../stores.svelte";
  import { btn, card, input, label } from "../ui";

  let file = $state<string | null>(null);
  let doEncrypt = $state(true);
  let doSign = $state(false);
  let recipients = $state<string[]>([]);
  let signer = $state("");
  let armor = $state(false);
  let busy = $state(false);
  let progress = $state({ done: 0, total: 0 });
  let outputPath = $state<string | null>(null);

  const secretKeys = $derived(keyring.list.filter((k) => k.has_secret && !k.revoked));
  const ready = $derived(
    !!file && (doEncrypt || doSign) && (!doEncrypt || recipients.length > 0) && (!doSign || !!signer),
  );

  onMount(() => {
    refreshKeys();
    const un = onProgress((p) => {
      if (busy && p.job === file) progress = { done: p.done, total: p.total };
    });
    return () => void un.then((f) => f());
  });

  $effect(() => {
    if (doSign && !signer && secretKeys.length) signer = secretKeys[0].fingerprint;
  });

  async function run() {
    if (!file) return;
    const suggested = `${file}.${armor ? "asc" : "gpg"}`;
    const target = await save({ defaultPath: suggested });
    if (!target) return;
    busy = true;
    outputPath = null;
    progress = { done: 0, total: 0 };
    try {
      const out = await withPassphrase(
        (passphrase) =>
          api.encryptFile({
            input_path: file!,
            output_path: target,
            recipients: doEncrypt ? recipients : [],
            sign_with: doSign ? signer : undefined,
            passphrase,
            armor,
          }),
        "Unlock signing key",
        "Enter the passphrase of the key you are signing with.",
      );
      if (out) {
        outputPath = out;
        toast("success", "File encrypted");
      }
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }
</script>

<h2 class="mb-4 text-lg font-semibold">Encrypt &amp; Sign</h2>

<div class="grid max-w-2xl gap-4">
  <FileDropzone path={file} onfile={(p) => ((file = p), (outputPath = null))} />

  <div class="{card} grid gap-4">
    <div class="flex flex-wrap gap-6 text-sm">
      <label class="flex items-center gap-2"><input type="checkbox" bind:checked={doEncrypt} /> Encrypt with public key(s)</label>
      <label class="flex items-center gap-2"><input type="checkbox" bind:checked={doSign} /> Sign with my private key</label>
    </div>

    {#if doEncrypt}
      <div><span class={label}>Recipients</span><RecipientSelect bind:selected={recipients} /></div>
    {/if}

    {#if doSign}
      <div>
        <label class={label} for="signer">Sign as</label>
        <select id="signer" class={input} bind:value={signer}>
          {#each secretKeys as k (k.fingerprint)}<option value={k.fingerprint}>{keyLabel(k)}</option>{/each}
        </select>
        {#if !secretKeys.length}<p class="mt-1 text-xs text-amber-600 dark:text-amber-400">No secret keys available. Generate one first.</p>{/if}
      </div>
    {/if}

    <fieldset class="flex gap-6 text-sm">
      <legend class={label}>Output format</legend>
      <label class="flex items-center gap-2"><input type="radio" name="fmt" checked={!armor} onchange={() => (armor = false)} /> Binary (.gpg)</label>
      <label class="flex items-center gap-2"><input type="radio" name="fmt" checked={armor} onchange={() => (armor = true)} /> ASCII armor (.asc)</label>
    </fieldset>
  </div>

  {#if busy}<ProgressBar done={progress.done} total={progress.total} />{/if}

  {#if outputPath}
    <div class="rounded-md border border-emerald-500/40 bg-emerald-50 px-3 py-2 text-sm text-emerald-900 dark:bg-emerald-950 dark:text-emerald-100">
      Saved to <span class="font-mono text-xs break-all">{outputPath}</span>
    </div>
  {/if}

  <div><button class={btn.primary} disabled={!ready || busy} onclick={run}>{busy ? "Working…" : doEncrypt ? "Encrypt" : "Sign"}</button></div>
</div>
