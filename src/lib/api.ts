import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  CertLevel,
  GraphData,
  KeyDetail,
  QrMode,
  QrView,
  RefreshReport,
  RemoteKey,
  ServerId,
  Trust,
  UploadReport,
  DecryptRequest,
  DecryptResult,
  EncryptRequest,
  GenerateKeyRequest,
  KeyInfo,
  Progress,
  TextDecryptResult,
  Team,
} from "./types";

export const api = {
  listKeys: () => invoke<KeyInfo[]>("list_keys"),
  generateKey: (request: GenerateKeyRequest) => invoke<KeyInfo>("generate_key", { request }),
  importKey: (armored: string) => invoke<KeyInfo[]>("import_key", { armored }),
  importKeyFile: (path: string) => invoke<KeyInfo[]>("import_key_file", { path }),
  exportKey: (fingerprint: string, secret: boolean, passphrase?: string) =>
    invoke<string>("export_key", { fingerprint, secret, passphrase }),
  exportKeyToFile: (fingerprint: string, secret: boolean, path: string, passphrase?: string) =>
    invoke<void>("export_key_to_file", { fingerprint, secret, path, passphrase }),
  deleteKey: (fingerprint: string) => invoke<void>("delete_key", { fingerprint }),

  encryptFile: (request: EncryptRequest) => invoke<string>("encrypt_file", { request }),
  sendByMail: (attachmentPath: string, to?: string, subject?: string, body?: string) =>
    invoke<void>("send_via_default_mail_client", { attachmentPath, to, subject, body }),
  decryptFile: (request: DecryptRequest) => invoke<DecryptResult>("decrypt_file", { request }),
  encryptText: (text: string, recipients: string[], signWith?: string, passphrase?: string) =>
    invoke<string>("encrypt_text", { text, recipients, signWith, passphrase }),
  keyDetail: (fingerprint: string) => invoke<KeyDetail>("key_detail", { fingerprint }),
  setOwnertrust: (fingerprint: string, level: Trust) =>
    invoke<KeyInfo>("set_ownertrust", { fingerprint, level }),
  trustGraph: () => invoke<GraphData>("trust_graph"),
  certifyKey: (request: {
    target: string;
    signer: string;
    level: CertLevel;
    user_ids: string[];
    passphrase?: string;
  }) => invoke<KeyInfo>("certify_key", { request }),
  lookupWkd: (email: string) => invoke<RemoteKey[]>("lookup_wkd", { email }),
  lookupKeyserver: (query: string, server: ServerId) =>
    invoke<RemoteKey[]>("lookup_keyserver", { query, server }),
  uploadKey: (fingerprint: string, server: ServerId) =>
    invoke<UploadReport>("upload_key", { fingerprint, server }),
  refreshKeys: (server: ServerId) => invoke<RefreshReport>("refresh_keys", { server }),

  qrCode: (fingerprint: string, mode: QrMode) => invoke<QrView>("qr_code", { fingerprint, mode }),
  qrPng: (fingerprint: string, mode: QrMode) => invoke<ArrayBuffer>("qr_png", { fingerprint, mode }),
  saveQr: (fingerprint: string, mode: QrMode, path: string) =>
    invoke<void>("save_qr", { fingerprint, mode, path }),
  importFromUri: (uri: string, server: ServerId) => invoke<KeyInfo>("import_from_uri", { uri, server }),

  listTeams: () => invoke<Team[]>("list_teams"),
  saveTeam: (name: string, members: string[], id?: string) => invoke<Team>("save_team", { id, name, members }),
  deleteTeam: (id: string) => invoke<void>("delete_team", { id }),

  decryptText: (armored: string, passphrase?: string) =>
    invoke<TextDecryptResult>("decrypt_text", { armored, passphrase }),
};

export function onProgress(handler: (p: Progress) => void): Promise<UnlistenFn> {
  return listen<Progress>("gpg://progress", (e) => handler(e.payload));
}
