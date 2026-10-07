const REPO = "EddyDevProject/AegisGPG";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)");

// ---- theme toggle
const themeBtn = $("#theme");
const isDark = () =>
  document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
const paintTheme = () => themeBtn.setAttribute("aria-label", isDark() ? "Switch to light mode" : "Switch to dark mode");
themeBtn.addEventListener("click", () => {
  const next = isDark() ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem("theme", next);
  } catch {}
  paintTheme();
});
paintTheme();

// ---- nav border once the page has scrolled (observer, not a scroll listener)
const nav = $("#nav");
const sentinel = document.createElement("div");
sentinel.setAttribute("aria-hidden", "true");
sentinel.className = "sr-only";
document.body.prepend(sentinel);
new IntersectionObserver(([e]) => nav.classList.toggle("scrolled", !e.isIntersecting)).observe(sentinel);

// ---- reveal on scroll
const revealables = $$(".reveal, .route-line");
if ("IntersectionObserver" in window && !reduceMotion.matches) {
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        e.target.classList.add("in");
        io.unobserve(e.target);
      }
    },
    { rootMargin: "0px 0px -8% 0px", threshold: 0.12 }
  );
  // short stagger between siblings that enter together
  $$(".sec-list, .bento, .os-grid, .route-line").forEach((group) =>
    $$(".reveal", group).forEach((el, i) => el.style.setProperty("--d", `${Math.min(i, 6) * 55}ms`))
  );
  revealables.forEach((el) => io.observe(el));
} else {
  revealables.forEach((el) => el.classList.add("in"));
}

// ---- the letter: seal and open (simulated, nothing is encrypted)
const env = $("#env");
const msg = $("#msg");
const armor = $("#sealed");
const sealBtn = $("#seal");
const stateEl = $("#state");
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const WIDTH = 46;

function seeded(text) {
  let h = 2166136261;
  for (const c of text) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
  return () => ((h = Math.imul(h ^ (h >>> 15), 2246822507) >>> 0), (h ^ (h >>> 13)) >>> 0);
}
function armored(text) {
  const rnd = seeded(text || "empty");
  const lines = ["-----BEGIN PGP MESSAGE-----", ""];
  const rows = 5;
  for (let r = 0; r < rows; r++) {
    let s = "";
    for (let i = 0; i < WIDTH; i++) s += B64[rnd() % 64];
    lines.push(s);
  }
  return lines.join("\n");
}
function scramble(target, done) {
  if (reduceMotion.matches) {
    armor.textContent = target;
    return done();
  }
  const start = performance.now();
  const dur = 520;
  const tick = (now) => {
    const t = Math.min(1, (now - start) / dur);
    let out = "";
    for (let i = 0; i < target.length; i++) {
      const ch = target[i];
      out += ch === "\n" || i / target.length < t ? ch : B64[(Math.random() * 64) | 0];
    }
    armor.textContent = out;
    t < 1 ? requestAnimationFrame(tick) : done();
  };
  requestAnimationFrame(tick);
}
let busy = false;
function setLabel(text, icon) {
  $("span", sealBtn).textContent = text;
  $("use", sealBtn).setAttribute("href", `/icons.svg#i-${icon}`);
}
function seal() {
  if (busy) return;
  busy = true;
  const target = armored(msg.value.trim());
  armor.hidden = false;
  armor.style.setProperty("min-height", `${msg.offsetHeight}px`);
  msg.hidden = true;
  scramble(target, () => {
    env.dataset.state = "sealed";
    stateEl.textContent = "Sealed for Bruno. Only Bruno can open it.";
    setLabel("Open as Bruno", "lock-key-open");
    busy = false;
  });
}
function open() {
  env.dataset.state = "open";
  armor.hidden = true;
  msg.hidden = false;
  stateEl.textContent = "Bruno opened it with his key. Anyone else sees only the block you just saw.";
  setLabel("Seal message", "lock-simple");
}
sealBtn.addEventListener("click", () => (env.dataset.state === "sealed" ? open() : seal()));
msg.addEventListener("input", () => {
  stateEl.textContent = "Anyone can read this.";
});

// ---- copy command
const copyBtn = $("#copy");
copyBtn?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("#cmd-text").textContent);
    copyBtn.classList.add("done");
    copyBtn.setAttribute("aria-label", "Copied");
    setTimeout(() => {
      copyBtn.classList.remove("done");
      copyBtn.setAttribute("aria-label", "Copy command");
    }, 1600);
  } catch {}
});

// ---- downloads: OS-aware, links from the latest GitHub release
const patterns = {
  "mac-arm": /aarch64\.dmg$/i,
  "mac-x64": /(x64|x86_64)\.dmg$/i,
  win: /x64-setup\.exe$/i,
  appimage: /\.AppImage$/i,
  deb: /\.deb$/i,
  rpm: /\.rpm$/i,
};
const ua = navigator.userAgent;
const os = /Windows/i.test(ua) ? "win" : /Mac/i.test(ua) && !/iPhone|iPad/i.test(ua) ? "mac" : /Linux|X11/i.test(ua) && !/Android/i.test(ua) ? "linux" : null;
const names = { win: "Windows", mac: "macOS", linux: "Linux" };

if (os) {
  $("#cta-label").textContent = `Download for ${names[os]}`;
  const card = $(`[data-os="${os}"]`);
  card?.classList.add("rec");
  card?.parentElement.prepend(card);
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
    $("#ver").textContent = `Free and open source under GPL-3.0. Latest version: ${rel.tag_name}.`;
    // Direct download for Windows and Linux; macOS needs a choice between Apple Silicon and Intel.
    const direct = os === "win" ? found.win : os === "linux" ? found.appimage : null;
    if (direct) $("#cta").href = direct;
  })
  .catch(() => {
    // Keep the static links to the Releases page.
  });
