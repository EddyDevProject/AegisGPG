<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "../api";
  import RecipientSelect from "../components/RecipientSelect.svelte";
  import SignatureBanner from "../components/SignatureBanner.svelte";
  import { errorMessage, prefs, refreshKeys, setEncryptToSelf, toast, withPassphrase, withSelf } from "../stores.svelte";
  import { btn, input, label } from "../ui";
  import type { SignatureStatus } from "../types";

  let mode = $state<"encrypt" | "decrypt">("encrypt");
  let text = $state("");
  let output = $state("");
  let recipients = $state<string[]>([]);
  let signatures = $state<SignatureStatus[] | null>(null);
  let busy = $state(false);

  onMount(refreshKeys);

  async function paste() {
    try {
      text = await navigator.clipboard.readText();
    } catch {
      toast("error", "Clipboard unavailable. Paste with Ctrl/Cmd+V instead.");
    }
  }

  async function copy() {
    await navigator.clipboard.writeText(output);
    toast("success", "Copied to clipboard");
  }

  async function run() {
    busy = true;
    output = "";
    signatures = null;
    try {
      if (mode === "encrypt") {
        output = await api.encryptText(text, withSelf(recipients));
      } else {
        const r = await withPassphrase(
          (passphrase) => api.decryptText(text, passphrase),
          "Unlock secret key",
          "This message is encrypted for a key protected by a passphrase.",
        );
        if (r) {
          output = r.text;
          signatures = r.signatures;
        }
      }
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }
</script>

<h2 class="mb-4 text-lg font-semibold">Quick Text</h2>

<div class="grid max-w-3xl gap-4">
  <div class="inline-flex w-fit rounded-md border border-zinc-300 p-0.5 dark:border-zinc-700" role="tablist">
    {#each ["encrypt", "decrypt"] as const as m}
      <button
        role="tab"
        aria-selected={mode === m}
        class="rounded px-3 py-1 text-sm capitalize {mode === m ? 'bg-accent text-white' : 'text-zinc-600 dark:text-zinc-400'}"
        onclick={() => ((mode = m), (output = ""), (signatures = null))}>{m}</button>
    {/each}
  </div>

  {#if mode === "encrypt"}
    <div><span class={label}>Recipients</span><RecipientSelect bind:selected={recipients} /></div>
    <label class="flex items-center gap-2 text-sm">
      <input type="checkbox" checked={prefs.encryptToSelf} onchange={(e) => setEncryptToSelf(e.currentTarget.checked)} />
      Also encrypt to myself <span class="text-xs text-zinc-500">(so I can decrypt it later)</span>
    </label>
  {/if}

  <div>
    <div class="mb-1 flex items-center justify-between">
      <label class="text-xs font-medium text-zinc-500" for="txt-in">{mode === "encrypt" ? "Message" : "Armored message"}</label>
      <button class="text-xs text-accent hover:underline" onclick={paste}>Paste from clipboard</button>
    </div>
    <textarea id="txt-in" class="{input} h-40 font-mono text-xs" bind:value={text}></textarea>
  </div>

  <div>
    <button class={btn.primary} disabled={busy || !text.trim() || (mode === "encrypt" && !recipients.length)} onclick={run}>
      {mode === "encrypt" ? "Encrypt" : "Decrypt"}
    </button>
  </div>

  {#if output}
    <div>
      <div class="mb-1 flex items-center justify-between">
        <span class={label}>Result</span>
        <button class="text-xs text-accent hover:underline" onclick={copy}>Copy</button>
      </div>
      <textarea class="{input} h-40 font-mono text-xs" readonly value={output} aria-label="Result"></textarea>
    </div>
  {/if}
  {#if signatures}<SignatureBanner {signatures} />{/if}
</div>
