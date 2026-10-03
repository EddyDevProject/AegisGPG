<script lang="ts">
  import Modal from "./Modal.svelte";
  import FileDropzone from "./FileDropzone.svelte";
  import { api } from "../api";
  import { errorMessage, refreshKeys, toast } from "../stores.svelte";
  import { btn, input } from "../ui";
  import type { ServerId } from "../types";

  let { onclose }: { onclose: () => void } = $props();
  let text = $state("");
  let busy = $state(false);
  let uri = $state("");
  let server = $state<ServerId>("keys_openpgp_org");

  async function fromUri() {
    busy = true;
    try {
      const k = await api.importFromUri(uri, server);
      await refreshKeys();
      toast("success", `Imported ${k.name ?? k.email ?? k.key_id}. Compare the fingerprint with the source.`);
      onclose();
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }

  async function pasteUri() {
    try {
      uri = (await navigator.clipboard.readText()).trim();
    } catch {
      toast("error", "Clipboard unavailable. Paste with Ctrl/Cmd+V instead.");
    }
  }

  async function run(job: () => Promise<{ length: number }>) {
    busy = true;
    try {
      const keys = await job();
      await refreshKeys();
      toast("success", `Imported ${keys.length} key${keys.length === 1 ? "" : "s"}`);
      onclose();
    } catch (e) {
      toast("error", errorMessage(e));
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Import key" {onclose}>
  <FileDropzone
    label="Drop a .asc / .pub / .key file, or click to browse"
    extensions={["asc", "pub", "key", "gpg", "pgp"]}
    onfile={(p) => run(() => api.importKeyFile(p))}
  />
  <p class="my-3 text-center text-xs text-zinc-500">or paste a scanned QR / <code>openpgp4fpr:</code> URI</p>
  <div class="grid grid-cols-[1fr_auto] gap-2">
    <input class={input} aria-label="openpgp4fpr URI" placeholder="openpgp4fpr:4B40DE2F…" bind:value={uri} />
    <button class={btn.outline} onclick={pasteUri}>Paste from scan</button>
    <select class={input} aria-label="Keyserver" bind:value={server}>
      <option value="keys_openpgp_org">keys.openpgp.org</option>
      <option value="keyserver_ubuntu_com">keyserver.ubuntu.com</option>
    </select>
    <button class={btn.primary} disabled={!uri.trim() || busy} onclick={fromUri}>{busy ? "Downloading…" : "Download key"}</button>
  </div>
  <p class="my-3 text-center text-xs text-zinc-500">or paste ASCII-armored text</p>
  <textarea
    class="{input} h-36 font-mono text-xs"
    placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
    aria-label="Armored key text"
    bind:value={text}
  ></textarea>
  {#snippet footer()}
    <button class={btn.ghost} onclick={onclose}>Cancel</button>
    <button class={btn.primary} disabled={!text.trim() || busy} onclick={() => run(() => api.importKey(text))}>Import</button>
  {/snippet}
</Modal>
