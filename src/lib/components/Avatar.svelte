<script lang="ts">
  import { prefs } from "../stores.svelte";

  let { email, name, size = 36 }: { email: string | null; name: string | null; size?: number } = $props();

  const hashes = new Map<string, Promise<string>>();
  function sha256(text: string): Promise<string> {
    let p = hashes.get(text);
    if (!p) {
      p = crypto.subtle
        .digest("SHA-256", new TextEncoder().encode(text))
        .then((b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join(""));
      hashes.set(text, p);
    }
    return p;
  }

  // Libravatar first, then Gravatar, then generated initials.
  let sources = $state<string[]>([]);
  let index = $state(0);

  $effect(() => {
    index = 0;
    sources = [];
    const addr = email?.trim().toLowerCase();
    if (!addr || !prefs.avatars || !crypto?.subtle) return;
    let cancelled = false;
    sha256(addr).then((h) => {
      if (cancelled) return;
      const px = size * 2; // crisp on HiDPI
      sources = [
        `https://seccdn.libravatar.org/avatar/${h}?s=${px}&d=404`,
        `https://gravatar.com/avatar/${h}?s=${px}&d=404`,
      ];
    });
    return () => (cancelled = true);
  });

  const initials = $derived(
    (name ?? email ?? "?")
      .split(/[\s@.]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((w) => w[0].toUpperCase())
      .join("") || "?",
  );
  const hue = $derived([...(email ?? name ?? "")].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 360, 7));
</script>

<span
  class="relative inline-flex shrink-0 items-center justify-center overflow-hidden rounded-full text-xs font-semibold text-white select-none"
  style:width="{size}px"
  style:height="{size}px"
  style:background="hsl({hue} 45% 45%)"
  style:font-size="{size * 0.38}px"
  aria-hidden="true"
>
  {initials}
  {#if sources[index]}
    {#key sources[index]}
      <img
        src={sources[index]}
        alt=""
        class="absolute inset-0 h-full w-full object-cover"
        referrerpolicy="no-referrer"
        onerror={() => (index += 1)}
      />
    {/key}
  {/if}
</span>
