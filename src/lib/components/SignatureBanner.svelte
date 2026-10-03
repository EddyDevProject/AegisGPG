<script lang="ts">
  import type { SignatureStatus } from "../types";

  let { signatures }: { signatures: SignatureStatus[] } = $props();

  const style = {
    valid: "border-emerald-500/40 bg-emerald-50 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-100",
    invalid: "border-red-500/40 bg-red-50 text-red-900 dark:bg-red-950 dark:text-red-100",
    unknown_signer: "border-amber-500/40 bg-amber-50 text-amber-900 dark:bg-amber-950 dark:text-amber-100",
  };
</script>

{#if signatures.length === 0}
  <div class="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-500 dark:border-zinc-700">Not signed</div>
{:else}
  {#each signatures as s}
    <div class="rounded-md border px-3 py-2 text-sm {style[s.status]}" role="status">
      {#if s.status === "valid"}
        <strong>Valid signature</strong> from {s.signer ?? "known key"}
      {:else if s.status === "invalid"}
        <strong>Invalid signature</strong>: the content may have been tampered with
      {:else}
        <strong>Unknown signer</strong>: import their public key to verify
      {/if}
      {#if s.fingerprint}<div class="mt-0.5 font-mono text-xs break-all opacity-80">{s.fingerprint}</div>{/if}
    </div>
  {/each}
{/if}
