// Runs before first paint: no flash of the wrong theme, and a hook for JS-only styles.
document.documentElement.classList.add("js");
try {
  const saved = localStorage.getItem("theme");
  if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
} catch {}
