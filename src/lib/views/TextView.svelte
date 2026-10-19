<script lang="ts">
  import InfoTip from "../components/InfoTip.svelte";
  import { onMount } from "svelte";
  import { api } from "../api";
  import RecipientSelect from "../components/RecipientSelect.svelte";
  import SignatureBanner from "../components/SignatureBanner.svelte";
  import { copySecret, errorMessage, keyLabel, keyring, prefs, refreshKeys, setEncryptToSelf, toast, withPassphrase, withSelf } from "../stores.svelte";
  import { btn, input, label } from "../ui";
  import type { SignatureStatus } from "../types";

  type Mode = "encrypt" | "decrypt" | "sign" | "verify";
  const modes: Mode[] = ["encrypt", "decrypt", "sign", "verify"];
  let mode = $state<Mode>("encrypt");
  let doSign = $state(false);
  let signer = $state("");
  let text = $state("");
  let output = $state("");
  let recipients = $state<string[]>([]);
  let signatures = $state<SignatureStatus[] | null>(null);
  let busy = $state(false);

  const secretKeys = $derived(keyring.list.filter((k) => k.has_secret && !k.revoked));
  const needsSigner = $derived(mode === "sign" || (mode === "encrypt" && doSign));
  const ready = $derived(
    !!text.trim() && (mode !== "encrypt" || recipients.length > 0) && (!needsSigner || !!signer),
  );

  onMount(refreshKeys);

  $effect(() => {
    if (needsSigner && !signer && secretKeys.length) signer = secretKeys[0].fingerprint;
  });

  async function paste() {
    try {
      text = await navigator.clipboard.readText();
    } catch {
      toast("error", "Clipboard unavailable. Paste with Ctrl/Cmd+V instead.");
    }
  }

  async function copy() {
    // Decrypted text is plaintext, so it is wiped from the clipboard later.
    if (mode === "decrypt") return copySecret(output, "Decrypted text copied");
    await navigator.clipboard.writeText(output);
    toast("success", "Copied to clipboard");
  }

  async function run() {
    busy = true;
    output = "";
    signatures = null;
    try {
      if (mode === "encrypt") {
        const by = doSign ? signer : undefined;
        const out = await withPassphrase(
          (passphrase) => api.encryptText(text, withSelf(recipients, by), by, passphrase),
          "Unlock secret key",
          "Enter the passphrase of the key you are signing with.",
        );
        if (out !== null) output = out;
      } else if (mode === "sign") {
        const out = await withPassphrase(
          (passphrase) => api.signText(text, signer, passphrase),
          "Unlock secret key",
          "Enter the passphrase of the key you are signing with.",
        );
        if (out !== null) output = out;
      } else if (mode === "verify") {
        const r = await api.verifyText(text);
        output = r.text;
        signatures = r.signatures;
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

<h2 class="mb-4 flex items-center gap-2 text-lg font-semibold">Quick Text <InfoTip text="Encrypt, decrypt, sign or verify short messages without files. The result is plain text you can paste into any chat or email. Signing keeps the message readable and adds a signature that proves it is yours." /></h2>

<div class="grid max-w-3xl gap-4">
  <div class="inline-flex w-fit rounded-md border border-zinc-300 p-0.5 dark:border-zinc-700" role="tablist">
    {#each modes as m}
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
      Also encrypt to myself <span class="text-xs text-zinc-500">(so I can decrypt it later)</span> <InfoTip text="Adds your own key to the recipients. Without it, you could not read the message you just encrypted for someone else." />
    </label>
    <label class="flex items-center gap-2 text-sm">
      <input type="checkbox" bind:checked={doSign} />
      Also sign with my key <InfoTip text="Proves the message is yours and was not changed. The recipient needs your public key to check it." />
    </label>
  {/if}

  {#if needsSigner}
    <div>
      <label class={label} for="txt-signer">Sign as</label>
      <select id="txt-signer" class={input} bind:value={signer}>
        {#each secretKeys as k (k.fingerprint)}<option value={k.fingerprint}>{keyLabel(k)}</option>{/each}
      </select>
      {#if !secretKeys.length}<p class="mt-1 text-xs text-amber-600 dark:text-amber-400">No secret keys available. Generate one first.</p>{/if}
    </div>
  {/if}

  <div>
    <div class="mb-1 flex items-center justify-between">
      <label class="text-xs font-medium text-zinc-500" for="txt-in">{{ encrypt: "Message", decrypt: "Armored message", sign: "Text to sign", verify: "Signed message" }[mode]}</label>
      <button class="text-xs text-accent hover:underline" onclick={paste}>Paste from clipboard</button>
    </div>
    <textarea id="txt-in" class="{input} h-40 font-mono text-xs" bind:value={text}></textarea>
  </div>

  <div>
    <button class={btn.primary} disabled={busy || !ready} onclick={run}>
      {{ encrypt: "Encrypt", decrypt: "Decrypt", sign: "Sign", verify: "Verify" }[mode]}
    </button>
  </div>

  {#if output}
    <div>
      <div class="mb-1 flex items-center justify-between">
        <span class={label}>{mode === "verify" ? "Signed text" : "Result"}</span>
        <button class="text-xs text-accent hover:underline" onclick={copy}>Copy</button>
      </div>
      <textarea class="{input} h-40 font-mono text-xs" readonly value={output} aria-label="Result"></textarea>
    </div>
  {/if}
  {#if signatures}<SignatureBanner {signatures} />{/if}
</div>
