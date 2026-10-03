import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";
import { readFileSync, writeFileSync } from "node:fs";

// Build number: bumped every time Vite starts (dev server or production build),
// so the version shown in the credits changes with every new run/build.
function nextBuild(): number {
  const file = new URL("./build-number.json", import.meta.url);
  let n = 0;
  try {
    n = JSON.parse(readFileSync(file, "utf8")).build ?? 0;
  } catch {}
  n += 1;
  writeFileSync(file, JSON.stringify({ build: n }) + "\n");
  return n;
}

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
const version = `${pkg.version}+${nextBuild()}`;

export default defineConfig({
  plugins: [tailwindcss(), svelte()],
  define: { __APP_VERSION__: JSON.stringify(version) },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**", "**/build-number.json"] },
  },
});
