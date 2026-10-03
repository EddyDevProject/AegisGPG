import { api } from "./api";
import type { AppError, KeyInfo, Trust } from "./types";

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
  resolve: null as null | ((v: string | null) => void),
});

/** Resolves with the passphrase, or null if cancelled. */
export function askPassphrase(title: string, description = "", error = ""): Promise<string | null> {
  return new Promise((resolve) => {
    Object.assign(passphrasePrompt, { open: true, title, description, error, resolve });
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
  for (;;) {
    try {
      return await run(pass);
    } catch (e) {
      const code = errorCode(e);
      if (code !== "passphrase_required" && code !== "wrong_passphrase") throw e;
      if (code === "wrong_passphrase") error = errorMessage(e);
      const p = await askPassphrase(title, description, error);
      if (p === null) return null;
      pass = p;
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
/** Avatars are fetched from third parties using a hash of the email. */
export const prefs = $state({ avatars: pref("avatars", true) });
export function setAvatars(on: boolean) {
  prefs.avatars = on;
  try {
    localStorage.setItem("avatars", on ? "1" : "0");
  } catch {}
}
