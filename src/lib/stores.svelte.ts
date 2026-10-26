import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { api } from "./api";
import type { AppError, KeyInfo, Team, Trust } from "./types";

// ------------------------------------------------------------- toasts ----
export type ToastKind = "success" | "error" | "info";
export const toasts = $state<{ id: number; kind: ToastKind; text: string }[]>([]);
let nextToast = 1;

export function toast(kind: ToastKind, text: string, ms = 4500) {
  const id = nextToast++;
  toasts.push({ id, kind, text });
  setTimeout(() => dismissToast(id), ms);
}
export function dismissToast(id: number) {
  const i = toasts.findIndex((t) => t.id === id);
  if (i >= 0) toasts.splice(i, 1);
}

export function errorCode(e: unknown): AppError["code"] | undefined {
  return typeof e === "object" && e !== null && "code" in e ? (e as AppError).code : undefined;
}
export function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (typeof e === "object" && e !== null && "message" in e) return String((e as AppError).message);
  return "Something went wrong";
}

// --------------------------------------------------------------- keys ----
export const keyring = $state({ list: [] as KeyInfo[], loading: false });

export async function refreshKeys() {
  keyring.loading = true;
  try {
    keyring.list = await api.listKeys();
  } catch (e) {
    toast("error", errorMessage(e));
  } finally {
    keyring.loading = false;
  }
}

// -------------------------------------------------------------- teams ----
export const teamStore = $state({ list: [] as Team[] });

export async function refreshTeams() {
  try {
    teamStore.list = await api.listTeams();
  } catch (e) {
    toast("error", errorMessage(e));
  }
}

export const keyLabel = (k: KeyInfo) =>
  `${k.name ?? k.email ?? "Unnamed"}${k.email && k.name ? ` <${k.email}>` : ""}`;
export const shortFp = (fp: string) => fp.slice(-16).replace(/(.{4})/g, "$1 ").trim();
export const fmtDate = (s: number | null) =>
  s === null ? "Never" : new Date(s * 1000).toLocaleDateString();

// -------------------------------------------------------------- theme ----
function initialTheme(): "light" | "dark" {
  try {
    const saved = localStorage.getItem("theme");
    if (saved === "light" || saved === "dark") return saved;
  } catch {}
  return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
export const theme = $state({ mode: initialTheme() });

export function applyTheme() {
  document.documentElement.classList.toggle("dark", theme.mode === "dark");
  try {
    localStorage.setItem("theme", theme.mode);
  } catch {}
}
export function toggleTheme() {
  theme.mode = theme.mode === "dark" ? "light" : "dark";
  applyTheme();
}

// ------------------------------------------- promise-based global dialogs ----
export const passphrasePrompt = $state({
  open: false,
  title: "",
  description: "",
  error: "",
  /** Open on the KleyKnox form instead of the key's passphrase. */
  kleyknox: false,
  /** KleyKnox form only, with no way back to a key passphrase (sidebar button). */
  kleyknoxOnly: false,
  resolve: null as null | ((v: string | null) => void),
});

/**
 * Resolves with the passphrase, or null if cancelled. An empty string means
 * the keys were unlocked with KleyKnox: retry without one, the backend has it.
 */
export function askPassphrase(title: string, description = "", error = "", kleyknox = false): Promise<string | null> {
  return new Promise((resolve) => {
    Object.assign(passphrasePrompt, { open: true, title, description, error, kleyknox, kleyknoxOnly: false, resolve });
  });
}

/** Opens the KleyKnox form on its own; resolves true once keys were unlocked. */
export function unlockWithKleyKnox(): Promise<boolean> {
  return new Promise((resolve) => {
    Object.assign(passphrasePrompt, {
      open: true,
      title: "Unlock with KleyKnox",
      description: "",
      error: "",
      kleyknox: true,
      kleyknoxOnly: true,
      resolve: (v: string | null) => resolve(v !== null),
    });
  });
}

export const confirmPrompt = $state({
  open: false,
  title: "",
  description: "",
  confirmLabel: "Confirm",
  resolve: null as null | ((v: boolean) => void),
});

export function askConfirm(title: string, description: string, confirmLabel = "Delete"): Promise<boolean> {
  return new Promise((resolve) => {
    Object.assign(confirmPrompt, { open: true, title, description, confirmLabel, resolve });
  });
}

/**
 * Runs `run` without a passphrase first; if the backend says one is needed
 * (or the one given was wrong) asks the user and retries. Resolves null if the
 * user cancels the prompt.
 */
export async function withPassphrase<T>(
  run: (passphrase?: string) => Promise<T>,
  title: string,
  description: string,
): Promise<T | null> {
  let pass: string | undefined;
  let error = "";
  // Offered first at most once: if KleyKnox did not hold this key, ask for its own passphrase.
  let tryKleyKnox = prefs.kleyknoxByDefault;
  for (;;) {
    try {
      return await run(pass);
    } catch (e) {
      const code = errorCode(e);
      if (code !== "passphrase_required" && code !== "wrong_passphrase") throw e;
      if (code === "wrong_passphrase") error = errorMessage(e);
      if (tryKleyKnox) await refreshKleyKnox();
      const p = await askPassphrase(title, description, error, tryKleyKnox && kleyknox.dir !== null);
      if (p === null) return null;
      if (p === "") tryKleyKnox = false;
      pass = p || undefined;
    }
  }
}

// ------------------------------------------------- contacts & trust ----
/** Fingerprint of the contact shown in the detail drawer (null = closed). */
export const ui = $state({ selected: null as string | null });

export const trustLabels: Record<Trust, string> = {
  unknown: "Unknown",
  none: "None",
  marginal: "Marginal",
  full: "Full",
  ultimate: "Ultimate",
};
export const trustLevels: Trust[] = ["unknown", "none", "marginal", "full", "ultimate"];

export const groupFp = (fp: string) => fp.replace(/(.{4})/g, "$1 ").trim();

export async function copyText(text: string, what = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
    toast("success", `${what} to clipboard`);
  } catch {
    toast("error", "Clipboard unavailable");
  }
}

function pref(key: string, fallback: boolean): boolean {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : v === "1";
  } catch {
    return fallback;
  }
}
/**
 * Avatars are fetched from third parties using a hash of the email, which
 * reveals the contact list: off until the user turns it on.
 */
export const prefs = $state({
  avatars: pref("avatars", false),
  encryptToSelf: pref("encryptToSelf", true),
  rememberPassphrase: pref("rememberPassphrase", true),
  clearClipboard: pref("clearClipboard", true),
  kleyknoxByDefault: pref("kleyknoxByDefault", true),
});

/** Seconds a copied secret (decrypted text, secret key) stays on the clipboard. */
const CLIPBOARD_CLEAR = 30;

export function setClearClipboard(on: boolean) {
  prefs.clearClipboard = on;
  try {
    localStorage.setItem("clearClipboard", on ? "1" : "0");
  } catch {}
}

/** Copies something secret; the clipboard is wiped after a delay unless that is turned off. */
export async function copySecret(text: string, what = "Copied") {
  try {
    if (prefs.clearClipboard) {
      await api.copySensitive(text, CLIPBOARD_CLEAR);
      toast("success", `${what} to clipboard, cleared in ${CLIPBOARD_CLEAR}s`);
    } else {
      await navigator.clipboard.writeText(text);
      toast("success", `${what} to clipboard`);
    }
  } catch {
    toast("error", "Clipboard unavailable");
  }
}

/** Seconds the backend keeps a typed passphrase in memory. */
const PASSPHRASE_TTL = 5 * 60;

/** Pushes the preference to the backend (also empties its cache when turned off). */
export function setRememberPassphrase(on: boolean) {
  prefs.rememberPassphrase = on;
  try {
    localStorage.setItem("rememberPassphrase", on ? "1" : "0");
  } catch {}
  void api.setPassphraseTtl(on ? PASSPHRASE_TTL : 0);
}
// The backend starts with caching on; apply a stored "off" straight away.
if (!prefs.rememberPassphrase) void api.setPassphraseTtl(0);
export function setAvatars(on: boolean) {
  prefs.avatars = on;
  try {
    localStorage.setItem("avatars", on ? "1" : "0");
  } catch {}
}

export function setEncryptToSelf(on: boolean) {
  prefs.encryptToSelf = on;
  try {
    localStorage.setItem("encryptToSelf", on ? "1" : "0");
  } catch {}
}

/** Own key to add as a recipient: `preferred` (the signer) if given, else the first valid secret key. */
export function ownKey(preferred?: string): string | undefined {
  const now = Date.now() / 1000;
  const mine = keyring.list.filter((k) => k.has_secret && !k.revoked && (k.expires === null || k.expires > now));
  return (mine.find((k) => k.fingerprint === preferred) ?? mine[0])?.fingerprint;
}

/** Recipients plus the user's own key when "encrypt to myself" is on. */
export function withSelf(recipients: string[], preferred?: string): string[] {
  const me = prefs.encryptToSelf ? ownKey(preferred) : undefined;
  return me && !recipients.includes(me) ? [...recipients, me] : recipients;
}

// ------------------------------------------------------------ updates ----
type UpdateStatus = "idle" | "checking" | "available" | "downloading" | "ready";
export const updater = $state({
  status: "idle" as UpdateStatus,
  version: "",
  notes: "",
  /** Download progress 0..1 (0 while the size is unknown) */
  progress: 0,
});
let pending: Update | null = null;

/** Looks for a newer release. `manual` also reports "up to date" and errors. */
export async function checkForUpdates(manual = false) {
  if (updater.status !== "idle") return;
  updater.status = "checking";
  try {
    const update = await check();
    if (update) {
      pending = update;
      Object.assign(updater, { status: "available", version: update.version, notes: update.body ?? "" });
      return;
    }
    if (manual) toast("success", "AegisGPG is up to date");
  } catch (e) {
    if (manual) toast("error", `Update check failed: ${errorMessage(e)}`);
  }
  updater.status = "idle";
}

/** Downloads, verifies (signature) and installs the update, then restarts. */
export async function installUpdate() {
  if (!pending || updater.status !== "available") return;
  updater.status = "downloading";
  updater.progress = 0;
  let total = 0;
  let done = 0;
  try {
    await pending.downloadAndInstall((ev) => {
      if (ev.event === "Started") total = ev.data.contentLength ?? 0;
      else if (ev.event === "Progress") {
        done += ev.data.chunkLength;
        updater.progress = total ? Math.min(done / total, 1) : 0;
      }
    });
    updater.status = "ready";
    await relaunch();
  } catch (e) {
    toast("error", `Update failed: ${errorMessage(e)}`);
    updater.status = "available";
  }
}

// -------------------------------------------------------------- kleyknox ----
/** The KleyKnox vault on a plugged-in stick, if any; refreshed on demand. */
export const kleyknox = $state({ dir: null as string | null, entries: [] as string[] });

export async function refreshKleyKnox() {
  try {
    Object.assign(kleyknox, await api.kleyknoxStatus());
  } catch {
    Object.assign(kleyknox, { dir: null, entries: [] });
  }
}

/** Ask for the KleyKnox passphrase instead of a key's own whenever the stick is plugged in. */
export function setKleyKnoxByDefault(on: boolean) {
  prefs.kleyknoxByDefault = on;
  try {
    localStorage.setItem("kleyknoxByDefault", on ? "1" : "0");
  } catch {}
}

/** How long keys unlocked with KleyKnox stay unlocked, in seconds (last choice is kept). */
export const kleyknoxTtls = [
  { seconds: 15 * 60, label: "15 minutes" },
  { seconds: 60 * 60, label: "1 hour" },
  { seconds: 2 * 3600, label: "2 hours" },
  { seconds: 8 * 3600, label: "8 hours" },
];

export function kleyknoxTtl(): number {
  try {
    const v = Number(localStorage.getItem("kleyknoxTtl"));
    if (kleyknoxTtls.some((t) => t.seconds === v)) return v;
  } catch {}
  return 2 * 3600;
}

export function setKleyKnoxTtl(seconds: number) {
  try {
    localStorage.setItem("kleyknoxTtl", String(seconds));
  } catch {}
}
