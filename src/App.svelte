<script lang="ts">
  import { fade } from "svelte/transition";
  import GlobalDialogs from "./lib/components/GlobalDialogs.svelte";
  import Toasts from "./lib/components/Toasts.svelte";
  import DecryptView from "./lib/views/DecryptView.svelte";
  import EncryptView from "./lib/views/EncryptView.svelte";
  import Icon, { type IconName } from "./lib/components/Icon.svelte";
  import ContactDrawer from "./lib/components/ContactDrawer.svelte";
  import DiscoverView from "./lib/views/DiscoverView.svelte";
  import GraphView from "./lib/views/GraphView.svelte";
  import KeysView from "./lib/views/KeysView.svelte";
  import TeamsView from "./lib/views/TeamsView.svelte";
  import TextView from "./lib/views/TextView.svelte";
  import { onMount } from "svelte";
  import { applyTheme, checkForUpdates, installUpdate, theme, toggleTheme, updater } from "./lib/stores.svelte";

  type Tab = "keys" | "teams" | "discover" | "graph" | "encrypt" | "decrypt" | "text";

  const tabs: { id: Tab; label: string; icon: IconName }[] = [
    { id: "keys", label: "Keys", icon: "key" },
    { id: "teams", label: "Teams", icon: "users" },
    { id: "discover", label: "Discover & Sync", icon: "globe" },
    { id: "graph", label: "Trust Graph", icon: "graph" },
    { id: "encrypt", label: "Encrypt & Sign", icon: "lock" },
    { id: "decrypt", label: "Decrypt & Verify", icon: "unlock" },
    { id: "text", label: "Quick Text", icon: "text" },
  ];

  let active = $state<Tab>("keys");

  $effect(applyTheme);

  // Silent check at startup (not in `tauri dev`, where there is nothing to update).
  onMount(() => {
    if (!import.meta.env.DEV) checkForUpdates();
  });
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
        <Icon name={tab.icon} class="size-[18px]" />{tab.label}
      </button>
    {/each}
    {#if updater.status === "available" || updater.status === "downloading" || updater.status === "ready"}
      <div class="mt-auto rounded-md border border-accent/40 bg-accent/10 p-2 text-xs" role="status">
        <div class="font-medium">Version {updater.version} available</div>
        {#if updater.status === "available"}
          <button class="mt-1.5 w-full rounded bg-accent px-2 py-1 text-white hover:brightness-110" onclick={installUpdate}>
            Install and restart
          </button>
        {:else}
          <div class="mt-1.5 h-1.5 overflow-hidden rounded bg-zinc-200 dark:bg-zinc-800">
            <div class="h-full bg-accent transition-[width]" style="width: {updater.status === 'ready' ? 100 : updater.progress * 100}%"></div>
          </div>
          <div class="mt-1 text-zinc-500">{updater.status === "ready" ? "Restarting…" : "Downloading…"}</div>
        {/if}
      </div>
    {/if}
    <button
      class="{updater.status === 'idle' || updater.status === 'checking' ? 'mt-auto ' : ''}flex items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm text-zinc-500 hover:bg-zinc-100 disabled:opacity-50 dark:hover:bg-zinc-900"
      disabled={updater.status !== "idle"}
      onclick={() => checkForUpdates(true)}
    >
      <Icon name="refresh" class="size-[18px] {updater.status === 'checking' ? 'animate-spin' : ''}" />{updater.status === "checking" ? "Checking…" : "Check for updates"}
    </button>
    <button
      class="flex items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-900"
      onclick={toggleTheme}
    >
      <Icon name={theme.mode === "dark" ? "sun" : "moon"} class="size-[18px]" />{theme.mode === "dark" ? "Light mode" : "Dark mode"}
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
        {:else if active === "teams"}<TeamsView />
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
