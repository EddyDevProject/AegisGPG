const REPO = "EddyDevProject/AegisGPG";
const $ = (s, r = document) => r.querySelector(s);

// ---- theme toggle
const themeBtn = $("#theme");
const isDark = () =>
  document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
const paint = () => (themeBtn.textContent = isDark() ? "☀" : "☾");
themeBtn.addEventListener("click", () => {
  const next = isDark() ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem("theme", next);
  } catch {}
  paint();
});
paint();

// ---- downloads: pick links from the latest GitHub release
const patterns = {
  "mac-arm": /aarch64\.dmg$/i,
  "mac-x64": /(x64|x86_64)\.dmg$/i,
  win: /x64-setup\.exe$/i,
  appimage: /\.AppImage$/i,
  deb: /\.deb$/i,
  rpm: /\.rpm$/i,
};
const ua = navigator.userAgent;
const os = /Windows/i.test(ua) ? "win" : /Mac/i.test(ua) ? "mac" : /Linux|X11/i.test(ua) && !/Android/i.test(ua) ? "linux" : null;
const names = { win: "Windows", mac: "macOS", linux: "Linux" };

if (os) {
  $("#cta-label").textContent = `Download for ${names[os]}`;
  $(`[data-os="${os}"]`)?.classList.add("rec");
}

fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers: { Accept: "application/vnd.github+json" } })
  .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
  .then((rel) => {
    const found = {};
    for (const [key, re] of Object.entries(patterns)) {
      const a = rel.assets.find((x) => re.test(x.name));
      if (!a) continue;
      found[key] = a.browser_download_url;
      const link = $(`[data-asset="${key}"]`);
      if (link) link.href = a.browser_download_url;
    }
    $("#ver").textContent = `Latest version: ${rel.tag_name}`;
    // Direct download for Windows/Linux; macOS needs a chip choice (arm64 vs Intel).
    const direct = os === "win" ? found.win : os === "linux" ? found.appimage : null;
    if (direct) $("#cta").href = direct;
    if (os === "mac") $("#cta-sub").textContent = "Choose Apple Silicon (M1 or later) or Intel below";
  })
  .catch(() => {
    // Keep the static links to the Releases page.
  });
