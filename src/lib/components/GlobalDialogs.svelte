<script lang="ts">
  import Modal from "./Modal.svelte";
  import { confirmPrompt, passphrasePrompt } from "../stores.svelte";
  import { btn, input } from "../ui";

  let value = $state("");

  function closePass(v: string | null) {
    passphrasePrompt.resolve?.(v);
    passphrasePrompt.open = false;
    value = "";
  }
  function closeConfirm(v: boolean) {
    confirmPrompt.resolve?.(v);
    confirmPrompt.open = false;
  }
</script>

{#if passphrasePrompt.open}
  <Modal title={passphrasePrompt.title} onclose={() => closePass(null)}>
    <form
      id="pp"
      onsubmit={(e) => {
        e.preventDefault();
        closePass(value);
      }}
    >
      {#if passphrasePrompt.description}
        <p class="mb-3 text-sm text-zinc-500">{passphrasePrompt.description}</p>
      {/if}
      <input type="password" class={input} placeholder="Passphrase" autocomplete="off" bind:value />
      {#if passphrasePrompt.error}
        <p class="mt-2 text-sm text-red-600 dark:text-red-400" role="alert">{passphrasePrompt.error}</p>
      {/if}
    </form>
    {#snippet footer()}
      <button class={btn.ghost} onclick={() => closePass(null)}>Cancel</button>
      <button class={btn.primary} type="submit" form="pp" disabled={!value}>Unlock</button>
    {/snippet}
  </Modal>
{/if}

{#if confirmPrompt.open}
  <Modal title={confirmPrompt.title} onclose={() => closeConfirm(false)}>
    <p class="text-sm text-zinc-600 dark:text-zinc-400">{confirmPrompt.description}</p>
    {#snippet footer()}
      <button class={btn.ghost} onclick={() => closeConfirm(false)}>Cancel</button>
      <button class={btn.danger} onclick={() => closeConfirm(true)}>{confirmPrompt.confirmLabel}</button>
    {/snippet}
  </Modal>
{/if}
