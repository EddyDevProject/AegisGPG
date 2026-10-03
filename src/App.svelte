<script lang="ts">
  import { fade } from "svelte/transition";
  import GlobalDialogs from "./lib/components/GlobalDialogs.svelte";
  import Toasts from "./lib/components/Toasts.svelte";
  import DecryptView from "./lib/views/DecryptView.svelte";
  import EncryptView from "./lib/views/EncryptView.svelte";
  import ContactDrawer from "./lib/components/ContactDrawer.svelte";
  import DiscoverView from "./lib/views/DiscoverView.svelte";
  import GraphView from "./lib/views/GraphView.svelte";
  import KeysView from "./lib/views/KeysView.svelte";
  import TextView from "./lib/views/TextView.svelte";
  import { applyTheme, theme, toggleTheme } from "./lib/stores.svelte";

  type Tab = "keys" | "discover" | "graph" | "encrypt" | "decrypt" | "text";

  const tabs: { id: Tab; label: string; icon: string }[] = [
    { id: "keys", label: "Keys", icon: "🔑" },
    { id: "discover", label: "Discover & Sync", icon: "🌐" },
    { id: "graph", label: "Trust Graph", icon: "🕸" },
    { id: "encrypt", label: "Encrypt & Sign", icon: "🔒" },
    { id: "decrypt", label: "Decrypt & Verify", icon: "🔓" },
    { id: "text", label: "Quick Text", icon: "✎" },
  ];

  let active = $state<Tab>("keys");

  $effect(applyTheme);
</script>

<div class="flex h-full">
  <nav class="flex w-56 shrink-0 flex-col gap-1 border-r border-zinc-200 p-3 dark:border-zinc-800" aria-label="Main">
    <h1 class="flex items-center gap-2 px-2 py-3 text-sm font-semibold tracking-tight">
      <img src="/favicon.svg" alt="" class="size-6" />AegisGPG
    </h1>
    {#each tabs as tab}
      <button
        class="flex items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors hover:bg-zinc-100 dark:hover:bg-zinc-900
          {active === tab.id ? 'bg-zinc-100 font-medium dark:bg-zinc-900' : 'text-zinc-600 dark:text-zinc-400'}"
        aria-current={active === tab.id ? "page" : undefined}
        onclick={() => (active = tab.id)}
      >
        <span aria-hidden="true" class="w-5 text-center">{tab.icon}</span>{tab.label}
      </button>
    {/each}
    <button
      class="mt-auto rounded-md px-2 py-1.5 text-left text-sm text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-900"
      onclick={toggleTheme}
    >
      {theme.mode === "dark" ? "☀ Light mode" : "☾ Dark mode"}
    </button>
    <footer class="mt-2 px-2 pt-3 text-center text-xs text-zinc-500 border-t border-zinc-200 dark:border-zinc-800">
      Made with <span class="text-red-500" aria-label="love">♥</span> by Edoardo Bavaro
      <div class="mt-0.5 font-mono text-[10px] opacity-70">v{__APP_VERSION__}</div>
    </footer>
  </nav>

  <main class="flex-1 overflow-auto p-6">
    {#key active}
      <div in:fade={{ duration: 120 }}>
        {#if active === "keys"}<KeysView />
        {:else if active === "discover"}<DiscoverView />
        {:else if active === "graph"}<GraphView />
        {:else if active === "encrypt"}<EncryptView />
        {:else if active === "decrypt"}<DecryptView />
        {:else}<TextView />{/if}
      </div>
    {/key}
  </main>
</div>

<ContactDrawer />
<GlobalDialogs />
<Toasts />
