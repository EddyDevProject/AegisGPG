<script lang="ts">
  let { text, align = "left" }: { text: string; align?: "left" | "right" } = $props();
  const id = `tip-${Math.random().toString(36).slice(2, 9)}`;
</script>

<span class="group relative inline-flex align-middle">
  <button
    type="button"
    class="inline-flex size-4 items-center justify-center rounded-full border border-zinc-400 text-[10px] leading-none font-semibold text-zinc-500 normal-case hover:border-accent hover:text-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent dark:border-zinc-600"
    aria-label="More information"
    aria-describedby={id}
  >i</button>
  <span
    {id}
    role="tooltip"
    class="pointer-events-none invisible absolute top-full z-30 mt-1.5 w-64 rounded-md border border-zinc-200 bg-white px-3 py-2 text-left text-xs font-normal tracking-normal text-zinc-700 normal-case opacity-0 shadow-lg transition-opacity group-focus-within:visible group-focus-within:opacity-100 group-hover:visible group-hover:opacity-100 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 {align === 'right' ? 'right-0' : 'left-0'}"
  >{text}</span>
</span>
