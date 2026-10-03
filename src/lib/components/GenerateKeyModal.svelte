<script lang="ts">
  import Modal from "./Modal.svelte";
  import { api } from "../api";
  import { errorMessage, refreshKeys, toast } from "../stores.svelte";
  import { btn, input, label } from "../ui";
  import type { Algorithm } from "../types";

  let { onclose }: { onclose: () => void } = $props();

  let name = $state("");
  let email = $state("");
  let comment = $state("");
  let passphrase = $state("");
  let confirm = $state("");
  let algorithm = $state<Algorithm>("ed25519");
  let validity = $state("730");
  let busy = $state(false);

  const mismatch = $derived(passphrase !== confirm);
  const valid = $derived(name.trim() !== "" && email.includes("@") && !mismatch);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    try {
      const days = Number(validity);
      await api.generateKey({
        name,
        email,
        comment: comment || undefined,
        passphrase: passphrase || undefined,
        algorithm,
        validity_days: days > 0 ? days : undefined,
      });
      await refreshKeys();
      toast("success", "Key generated");
      onclose();
    } catch (err) {
      toast("error", errorMessage(err));
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Generate key" {onclose}>
  <form id="gen" class="grid gap-3" onsubmit={submit}>
    <div><label class={label} for="g-name">Full name</label><input id="g-name" class={input} bind:value={name} required /></div>
    <div><label class={label} for="g-email">Email</label><input id="g-email" type="email" class={input} bind:value={email} required /></div>
    <div><label class={label} for="g-comment">Comment (optional)</label><input id="g-comment" class={input} bind:value={comment} /></div>
    <div class="grid grid-cols-2 gap-3">
      <div>
        <label class={label} for="g-algo">Algorithm</label>
        <select id="g-algo" class={input} bind:value={algorithm}>
          <option value="ed25519">Ed25519 / Cv25519 (recommended)</option>
          <option value="rsa4096">RSA 4096</option>
        </select>
      </div>
      <div>
        <label class={label} for="g-valid">Valid for (days, 0 = never)</label>
        <input id="g-valid" type="number" min="0" class={input} bind:value={validity} />
      </div>
    </div>
    <div class="grid grid-cols-2 gap-3">
      <div><label class={label} for="g-pass">Passphrase</label><input id="g-pass" type="password" autocomplete="new-password" class={input} bind:value={passphrase} /></div>
      <div><label class={label} for="g-conf">Confirm</label><input id="g-conf" type="password" autocomplete="new-password" class={input} bind:value={confirm} /></div>
    </div>
    {#if mismatch}<p class="text-sm text-red-600 dark:text-red-400" role="alert">Passphrases do not match</p>{/if}
    {#if !passphrase}<p class="text-xs text-amber-600 dark:text-amber-400">Without a passphrase the secret key is stored unprotected on disk.</p>{/if}
    {#if algorithm === "rsa4096"}<p class="text-xs text-zinc-500">RSA 4096 generation can take several seconds.</p>{/if}
  </form>
  {#snippet footer()}
    <button class={btn.ghost} onclick={onclose}>Cancel</button>
    <button class={btn.primary} type="submit" form="gen" disabled={!valid || busy}>{busy ? "Generating…" : "Generate"}</button>
  {/snippet}
</Modal>
