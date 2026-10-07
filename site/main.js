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

// ---- nav rule once the page has scrolled (observer, not a scroll listener)
const nav = $("#nav");
const sentinel = document.createElement("div");
sentinel.className = "sr-only";
sentinel.setAttribute("aria-hidden", "true");
document.body.prepend(sentinel);
new IntersectionObserver(([e]) => nav.classList.toggle("scrolled", !e.isIntersecting)).observe(sentinel);

// ---- reveal on scroll, short stagger between siblings
const revealables = $$(".reveal");
if ("IntersectionObserver" in window && !reduceMotion.matches) {
  $$(".manifest, .log, .checks, .os-grid, .qa").forEach((g) =>
    $$(".reveal", g).forEach((el, i) => el.style.setProperty("--d", `${Math.min(i, 6) * 50}ms`))
  );
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        e.target.classList.add("in");
        io.unobserve(e.target);
      }
    },
    { rootMargin: "0px 0px -8% 0px", threshold: 0.1 }
  );
  revealables.forEach((el) => io.observe(el));
} else {
  revealables.forEach((el) => el.classList.add("in"));
}

// ---- the bag: hold to seal, then open as the recipient or as anyone else (simulated)
const bag = $("#bag");
const msg = $("#msg");
const cipher = $("#cipher");
const sealBtn = $("#seal");
const sealLabel = $("#seal-l");
const pair = $("#pair");
const statusEl = $("#status-t");
const sealNo = $("#seal-no");
const stamp = $("#stamp");
const hint = $("#hint");
const tapeText = $(".tape-text", bag);
const tape = $(".tape", bag);
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HOLD_MS = 900;
const COLS = 28;

function seeded(text) {
  let h = 2166136261;
  for (const c of text) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
  return () => ((h = Math.imul(h ^ (h >>> 15), 2246822507) >>> 0), (h ^ (h >>> 13)) >>> 0);
}
function armored(text) {
  const rnd = seeded(text || "empty");
  const rows = [];
  for (let r = 0; r < 5; r++) {
    let s = "";
    for (let i = 0; i < COLS; i++) s += B64[rnd() % 64];
    rows.push(s);
  }
  return rows.join("\n");
}
function sealNumber(text) {
  const rnd = seeded(text || "empty");
  const g = () => (rnd() % 0x10000).toString(16).toUpperCase().padStart(4, "0");
  return `No. ${g()} ${g()} ${g()}`;
}
function scramble(target, done) {
  cipher.textContent = target;
  if (reduceMotion.matches) return done();
  const start = performance.now();
  const dur = 520;
  const tick = (now) => {
    const t = Math.min(1, (now - start) / dur);
    let out = "";
    for (let i = 0; i < target.length; i++) {
      const ch = target[i];
      out += ch === "\n" || i / target.length < t ? ch : B64[(Math.random() * 64) | 0];
    }
    cipher.textContent = out;
    t < 1 ? requestAnimationFrame(tick) : done();
  };
  requestAnimationFrame(tick);
}
function showStamp(text, ok) {
  stamp.textContent = text;
  stamp.classList.toggle("ok", ok);
  stamp.classList.remove("on");
  void stamp.offsetWidth; // restart the transition
  stamp.classList.add("on");
}
function setState(state, text) {
  bag.dataset.state = state;
  statusEl.textContent = text;
}

let busy = false;
function seal() {
  if (busy || bag.dataset.state !== "open") return;
  busy = true;
  const text = msg.value.trim();
  scramble(armored(text), () => {
    sealNo.textContent = sealNumber(text);
    setState("sealed", "Sealed for Bruno. Only Bruno can open it.");
    sealBtn.hidden = true;
    pair.hidden = false;
    hint.textContent = "Now try to open it, as Bruno and as anyone else.";
    showStamp("Sealed", true);
    $("#open-ok").focus({ preventScroll: true });
    busy = false;
  });
}
function reopen(state, msgText) {
  setState(state, msgText);
}
$("#open-ok").addEventListener("click", () => {
  tapeText.dataset.void = "false";
  stamp.classList.remove("on");
  setState("open", "Bruno opened it with his key. Anyone else sees only the block you just saw.");
  pair.hidden = true;
  sealBtn.hidden = false;
  sealLabel.textContent = "Hold to seal again";
  sealNo.innerHTML = "No. &mdash; &mdash; &mdash;";
  hint.textContent = "Press and hold, or press Enter. This is a demo: nothing is encrypted in your browser.";
  sealBtn.focus({ preventScroll: true });
});
$("#open-no").addEventListener("click", () => {
  tapeText.dataset.void = "true";
  reopen("void", "Access denied. Without Bruno's key it stays unreadable.");
  showStamp("Void", false);
  tape.classList.remove("shake");
  void tape.offsetWidth;
  tape.classList.add("shake");
});
msg.addEventListener("input", () => {
  statusEl.textContent = "Open. Anyone can read this.";
});

// Press and hold (pointer), or Enter / Space (keyboard, instant: no animation, no wait).
let holdTimer = 0;
const cancelHold = () => {
  clearTimeout(holdTimer);
  holdTimer = 0;
  sealBtn.classList.remove("holding");
};
sealBtn.addEventListener("pointerdown", (e) => {
  if (e.button !== 0 || busy) return;
  sealBtn.setPointerCapture(e.pointerId);
  sealBtn.classList.add("holding");
  holdTimer = setTimeout(() => {
    cancelHold();
    seal();
  }, HOLD_MS);
});
["pointerup", "pointercancel", "lostpointercapture"].forEach((t) => sealBtn.addEventListener(t, cancelHold));
sealBtn.addEventListener("keydown", (e) => {
  if ((e.key === "Enter" || e.key === " ") && !e.repeat) {
    e.preventDefault();
    seal();
  }
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
    $("#ver-short").textContent = rel.tag_name;
    const direct = os === "win" ? found.win : os === "linux" ? found.appimage : null;
    if (direct) $("#cta").href = direct;
  })
  .catch(() => {
    // Keep the static links to the Releases page.
  });
