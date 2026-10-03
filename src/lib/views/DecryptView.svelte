<script lang="ts">
  import { onMount } from "svelte";
  import { api, onProgress } from "../api";
  import FileDropzone from "../components/FileDropzone.svelte";
  import ProgressBar from "../components/ProgressBar.svelte";
  import SignatureBanner from "../components/SignatureBanner.svelte";
  import { errorMessage, refreshKeys, toast, withPassphrase } from "../stores.svelte";
  import { btn, card } from "../ui";
  import type { DecryptResult } from "../types";

  let file = $state<string | null>(null);
  let busy = $state(false);
  let progress = $state({ done: 0, total: 0 });
  let result = $state<DecryptResult | null>(null);
  let failure = $state<string | null>(null);

  onMount(() => {
    refreshKeys();
    const un = onProgress((p) => {
      if (busy && p.job === file) progress = { done: p.done, total: p.total };
    });
    return () => void un.then((f) => f());
  });

  async function run() {
    if (!file) return;
    busy = true;
    result = null;
    failure = null;
    progress = { done: 0, total: 0 };
    try {
      const r = await withPassphrase(
        (passphrase) => api.decryptFile({ input_path: file!, passphrase }),
        "Unlock secret key",
        "This message is encrypted for a key protected by a passphrase.",
      );
      if (r) {
        result = r;
        toast("success", "File decrypted");
      }
    } catch (e) {
      failure = errorMessage(e);
      toast("error", failure);
    } finally {
      busy = false;
    }
  }
</script>

<h2 class="mb-4 text-lg font-semibold">Decrypt &amp; Verify</h2>

<div class="grid max-w-2xl gap-4">
  <FileDropzone
    path={file}
    label="Drop an encrypted file (.gpg, .asc, .pgp)"
    extensions={["gpg", "asc", "pgp"]}
    onfile={(p) => ((file = p), (result = null), (failure = null))}
  />

  {#if busy}<ProgressBar done={progress.done} total={progress.total} />{/if}

  {#if failure}
    <div class="rounded-md border border-red-500/40 bg-red-50 px-3 py-2 text-sm text-red-900 dark:bg-red-950 dark:text-red-100" role="alert">{failure}</div>
  {/if}

  {#if result}
    <div class="{card} grid gap-3">
      <div class="text-sm font-medium text-emerald-600 dark:text-emerald-400">Decryption successful</div>
      <div>
        <div class="text-xs text-zinc-500">Saved to</div>
        <div class="font-mono text-xs break-all">{result.output_path}</div>
      </div>
      <SignatureBanner signatures={result.signatures} />
    </div>
  {/if}

  <div><button class={btn.primary} disabled={!file || busy} onclick={run}>{busy ? "Working…" : "Decrypt"}</button></div>
</div>
