// Shared Tailwind class recipes.
const base =
  "inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-50";

export const btn = {
  primary: `${base} bg-accent text-white hover:brightness-110`,
  ghost: `${base} text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800`,
  outline: `${base} border border-zinc-300 hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-800`,
  danger: `${base} bg-red-600 text-white hover:bg-red-500`,
};

export const input =
  "w-full rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm placeholder:text-zinc-400 focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/30 dark:border-zinc-700 dark:bg-zinc-900";

export const card = "rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900";
export const label = "mb-1 block text-xs font-medium text-zinc-500";
