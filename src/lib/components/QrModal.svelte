<script lang="ts">
  import { save } from "@tauri-apps/plugin-dialog";
  import Modal from "./Modal.svelte";
  import { api } from "../api";
  import { copyText, errorCode, errorMessage, groupFp, keyLabel, toast } from "../stores.svelte";
  import { btn } from "../ui";
  import type { KeyInfo, QrMode, QrView } from "../types";

  let { key, onclose }: { key: KeyInfo; onclose: () => void } = $props();

  let mode = $state<QrMode>("fingerprint");
  let qr = $state<QrView | null>(null);
  let tooLarge = $state(false);
  let loading = $state(false);

  const modes: { id: QrMode; label: string; hint: string }[] = [
    { id: "fingerprint", label: "Fingerprint", hint: "Compact and reliable. The other device downloads the key from a keyserver." },
    { id: "key", label: "Full public key", hint: "The whole ASCII-armored key. Works offline, but only for compact keys." },
    { id: "url", label: "Keyserver link", hint: "A link to the key on keys.openpgp.org (the key must be published there)." },
  ];

  // Re-render whenever the mode changes; ignore stale answers.
  $effect(() => {
    const m = mode;
    loading = true;
    tooLarge = false;
    api.qrCode(key.fingerprint, m).then(
      (r) => {
        if (m !== mode) return;
        qr = r;
        loading = false;
      },
      (e) => {
        if (m !== mode) return;
        qr = null;
        loading = false;
        if (errorCode(e) === "qr_too_large") tooLarge = true;
        else toast("error", errorMessage(e));
      },
    );
  });

  async function saveImage() {
    const path = await save({
      defaultPath: `${key.key_id}-${mode}.png`,
      filters: [
        { name: "PNG image", extensions: ["png"] },
        { name: "SVG image", extensions: ["svg"] },
      ],
    });
    if (!path) return;
    try {
      await api.saveQr(key.fingerprint, mode, path);
      toast("success", "QR code saved");
    } catch (e) {
      toast("error", errorMessage(e));
    }
  }

  async function copyImage() {
    try {
      const png = await api.qrPng(key.fingerprint, mode);
      await navigator.clipboard.write([new ClipboardItem({ "image/png": new Blob([png], { type: "image/png" }) })]);
      toast("success", "QR image copied to clipboard");
    } catch (e) {
      toast("error", errorCode(e) ? errorMessage(e) : "Could not copy the image on this system. Save it as a file instead.");
    }
  }
</script>

<Modal title="Share via QR code" {onclose}>
  <p class="mb-3 truncate text-sm text-zinc-500">{keyLabel(key)}</p>

  <div class="mb-2 inline-flex w-full rounded-md border border-zinc-300 p-0.5 dark:border-zinc-700" role="tablist">
    {#each modes as m}
      <button
        role="tab"
        aria-selected={mode === m.id}
        class="flex-1 rounded px-2 py-1 text-sm {mode === m.id ? 'bg-accent text-white' : 'text-zinc-600 dark:text-zinc-400'}"
        onclick={() => (mode = m.id)}>{m.label}</button>
    {/each}
  </div>
  <p class="mb-3 text-xs text-zinc-500">{modes.find((m) => m.id === mode)?.hint}</p>

  <!-- Always black-on-white with a quiet zone, even in dark mode. -->
  <div class="mx-auto flex aspect-square w-full max-w-72 items-center justify-center overflow-hidden rounded-lg bg-white shadow-inner ring-1 ring-zinc-200 dark:ring-zinc-700">
    {#if tooLarge}
      <div class="p-4 text-center text-sm text-amber-700" role="alert">
        <strong>Key too large for a single QR code.</strong>
        <p class="mt-1 text-xs">Show the keyserver link or the fingerprint instead.</p>
        <div class="mt-3 flex justify-center gap-2">
          <button class={btn.outline} onclick={() => (mode = "url")}>Keyserver link</button>
          <button class={btn.outline} onclick={() => (mode = "fingerprint")}>Fingerprint</button>
        </div>
      </div>
    {:else if qr}
      <div class="h-full w-full [&>svg]:h-full [&>svg]:w-full" role="img" aria-label="QR code for {keyLabel(key)}">{@html qr.svg}</div>
    {:else if loading}
      <span class="text-sm text-zinc-400">Generating…</span>
    {/if}
  </div>
  {#if qr && mode === "key"}
    <p class="mt-1 text-center text-xs text-zinc-500">{qr.bytes} bytes · QR version {qr.version} · error correction {qr.ec}</p>
  {/if}

  <div class="mt-4">
    <div class="flex items-start gap-2">
      <code class="flex-1 font-mono text-xs leading-relaxed break-all">{groupFp(key.fingerprint)}</code>
      <button class={btn.outline} onclick={() => copyText(key.fingerprint, "Fingerprint copied")}>Copy fingerprint</button>
    </div>
  </div>

  {#snippet footer()}
    <button class={btn.ghost} onclick={onclose}>Close</button>
    <button class={btn.outline} disabled={!qr} onclick={copyImage}>Copy image</button>
    <button class={btn.primary} disabled={!qr} onclick={saveImage}>Save as PNG / SVG…</button>
  {/snippet}
</Modal>
