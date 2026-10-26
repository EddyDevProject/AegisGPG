//! Tauri IPC surface. Heavy work runs on blocking threads so the UI stays live.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{async_runtime::spawn_blocking, AppHandle, Emitter, State};
use sequoia_openpgp::cert as openpgp_cert;
use zeroize::Zeroizing;

use crate::gpg::backup;
use crate::gpg::revoke::{self, Reason};
use crate::gpg::crypto::{self, EncryptOptions, SignatureStatus, Unlocked};
use crate::gpg::certify::{self, Level};
use crate::gpg::keys::{self, GenerateKeyRequest, KeyInfo, SubkeyInfo};
use crate::gpg::kleyknox;
use crate::gpg::net::{self, Server, UploadReport};
use crate::gpg::passphrase_cache::PassphraseCache;
use crate::gpg::qr;
use crate::gpg::store::KeyStore;
use crate::gpg::teams::{Team, TeamStore};
use crate::gpg::wot::{self, Graph, Trust};
use crate::gpg::{GpgError, Result};

const CHUNK: usize = 256 * 1024;

fn secret(s: Option<String>) -> Option<Zeroizing<String>> {
    s.filter(|p| !p.is_empty()).map(Zeroizing::new)
}

/// The passphrase to use for one operation: what the user just typed, else a cached one.
struct Unlock {
    pass: Option<Zeroizing<String>>,
    typed: bool,
}

impl Unlock {
    fn new(cache: &PassphraseCache, fingerprint: Option<&str>, typed: Option<String>) -> Self {
        match secret(typed) {
            Some(pass) => Self { pass: Some(pass), typed: true },
            None => Self { pass: fingerprint.and_then(|fp| cache.get(fp)), typed: false },
        }
    }

    fn as_str(&self) -> Option<&str> {
        self.pass.as_ref().map(|p| p.as_str())
    }

    /// Remembers a typed passphrase that worked; forgets a cached one that no
    /// longer does (the caller then simply asks the user again).
    fn settle<T>(&self, cache: &PassphraseCache, fingerprint: Option<&str>, result: Result<T>) -> Result<T> {
        let (Some(fp), Some(pass)) = (fingerprint, &self.pass) else { return result };
        match &result {
            Ok(_) if self.typed => cache.store(fp, pass),
            Err(GpgError::WrongPassphrase) if !self.typed => {
                cache.forget(fp);
                return Err(GpgError::PassphraseRequired);
            }
            _ => {}
        }
        result
    }
}

fn join_err(e: tauri::Error) -> GpgError {
    GpgError::Other(format!("Background task failed: {e}"))
}

// ---------------------------------------------------------------- keys ----

/// Describes every key in the keyring, including computed trust/validity.
fn describe_all(store: &KeyStore) -> Result<Vec<KeyInfo>> {
    let certs = store.all()?;
    let owner = store.ownertrust_map(&certs);
    let edges = wot::certifications(&certs);
    let levels = wot::levels(&certs, &owner, &edges);
    let none = HashMap::new();
    Ok(certs
        .iter()
        .map(|c| {
            let fp = c.fingerprint().to_hex();
            keys::info(c, owner[&fp], levels.uid.get(&fp).unwrap_or(&none))
        })
        .collect())
}

fn describe_one(store: &KeyStore, fingerprint: &str) -> Result<KeyInfo> {
    describe_all(store)?
        .into_iter()
        .find(|k| k.fingerprint.eq_ignore_ascii_case(fingerprint))
        .ok_or_else(|| GpgError::KeyNotFound(fingerprint.to_string()))
}

#[tauri::command]
pub fn list_keys(store: State<'_, KeyStore>) -> Result<Vec<KeyInfo>> {
    let mut list = describe_all(&store)?;
    list.sort_by(|a, b| a.name.cmp(&b.name).then(a.fingerprint.cmp(&b.fingerprint)));
    Ok(list)
}

#[tauri::command]
pub async fn generate_key(
    store: State<'_, KeyStore>,
    request: GenerateKeyRequest,
) -> Result<KeyInfo> {
    // RSA-4096 generation takes seconds: keep it off the IPC thread.
    let cert = spawn_blocking(move || keys::generate(request))
        .await
        .map_err(join_err)??;
    let cert = store.put(cert)?;
    describe_one(&store, &cert.fingerprint().to_hex())
}

#[tauri::command]
pub fn import_key(store: State<'_, KeyStore>, armored: String) -> Result<Vec<KeyInfo>> {
    import_bytes(&store, armored.as_bytes())
}

#[tauri::command]
pub fn import_key_file(store: State<'_, KeyStore>, path: String) -> Result<Vec<KeyInfo>> {
    // Keys are small; refuse anything absurd rather than reading it all.
    if fs::metadata(&path)?.len() > 16 * 1024 * 1024 {
        return Err(GpgError::InvalidInput("File is too large to be a key".into()));
    }
    import_bytes(&store, &fs::read(path)?)
}

fn import_bytes(store: &KeyStore, data: &[u8]) -> Result<Vec<KeyInfo>> {
    let mut fps = Vec::new();
    for cert in keys::parse(data)? {
        fps.push(store.put(cert)?.fingerprint().to_hex());
    }
    Ok(describe_all(store)?
        .into_iter()
        .filter(|k| fps.contains(&k.fingerprint))
        .collect())
}

#[tauri::command]
pub fn export_key(
    store: State<'_, KeyStore>,
    fingerprint: String,
    secret: bool,
    passphrase: Option<String>,
) -> Result<String> {
    let pass = self::secret(passphrase);
    let cert = store.get(&fingerprint)?;
    let bytes = keys::export(&cert, secret, pass.as_ref().map(|p| p.as_str()))?;
    String::from_utf8(bytes).map_err(|_| GpgError::Other("Export produced invalid text".into()))
}

#[tauri::command]
pub fn export_key_to_file(
    store: State<'_, KeyStore>,
    fingerprint: String,
    secret: bool,
    path: String,
    passphrase: Option<String>,
) -> Result<()> {
    let pass = self::secret(passphrase);
    let cert = store.get(&fingerprint)?;
    let bytes = keys::export(&cert, secret, pass.as_ref().map(|p| p.as_str()))?;
    if secret {
        // Secret key backups must not be readable by other local users.
        crate::gpg::store::write_private(Path::new(&path), &bytes)?;
    } else {
        fs::write(path, bytes)?;
    }
    Ok(())
}

#[tauri::command]
pub fn delete_key(store: State<'_, KeyStore>, fingerprint: String) -> Result<()> {
    store.delete(&fingerprint)
}

// ------------------------------------------------------------ teams ----

#[tauri::command]
pub fn list_teams(teams: State<'_, TeamStore>) -> Vec<Team> {
    teams.list()
}

#[tauri::command]
pub fn save_team(
    teams: State<'_, TeamStore>,
    id: Option<String>,
    name: String,
    members: Vec<String>,
) -> Result<Team> {
    teams.save(id, name, members)
}

#[tauri::command]
pub fn delete_team(teams: State<'_, TeamStore>, id: String) -> Result<()> {
    teams.delete(&id)
}

// ------------------------------------------------------ progress + paths ----

#[derive(Clone, Serialize)]
struct Progress {
    job: String,
    done: u64,
    total: u64,
}

/// Reader adapter that emits throttled progress events.
struct ProgressReader<R> {
    inner: R,
    app: AppHandle,
    job: String,
    done: u64,
    total: u64,
    last: Instant,
}

impl<R> ProgressReader<R> {
    fn new(inner: R, app: AppHandle, job: &Path, total: u64) -> Self {
        Self {
            inner,
            app,
            job: job.to_string_lossy().into_owned(),
            done: 0,
            total,
            last: Instant::now() - Duration::from_secs(1),
        }
    }

    fn emit(&self) {
        let _ = self.app.emit(
            "gpg://progress",
            Progress { job: self.job.clone(), done: self.done, total: self.total },
        );
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.done += n as u64;
        if n == 0 || self.last.elapsed() >= Duration::from_millis(80) {
            self.last = Instant::now();
            self.emit();
        }
        Ok(n)
    }
}

fn default_output(input: &str, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{input}.{suffix}"))
}

/// Never overwrite silently when the caller did not choose the output.
fn unique(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }
    for n in 1.. {
        let mut name = path.file_stem().unwrap_or_default().to_os_string();
        name.push(format!(" ({n})"));
        if let Some(ext) = path.extension() {
            name.push(".");
            name.push(ext);
        }
        let candidate = path.with_file_name(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

// ------------------------------------------------------------ files ----

#[derive(Deserialize)]
pub struct EncryptRequest {
    input_path: String,
    output_path: Option<String>,
    recipients: Vec<String>,
    sign_with: Option<String>,
    passphrase: Option<String>,
    armor: bool,
}

#[tauri::command]
pub async fn encrypt_file(
    app: AppHandle,
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    request: EncryptRequest,
) -> Result<String> {
    let recipients = request
        .recipients
        .iter()
        .map(|fp| store.get(fp).map_err(|_| GpgError::MissingRecipient(fp.clone())))
        .collect::<Result<Vec<_>>>()?;
    let signer = request.sign_with.as_deref().map(|fp| store.get(fp)).transpose()?;
    let sign_fp = request.sign_with.clone();
    let unlock = Unlock::new(&cache, sign_fp.as_deref(), request.passphrase);

    let out_path = request
        .output_path
        .map(PathBuf::from)
        .unwrap_or_else(|| unique(default_output(&request.input_path, if request.armor { "asc" } else { "gpg" })));
    let in_path = PathBuf::from(request.input_path);
    let armor = request.armor;

    let pass = unlock.pass.clone();
    let result = spawn_blocking(move || -> Result<String> {
        let file = File::open(&in_path)?;
        let total = file.metadata()?.len();
        let reader = ProgressReader::new(BufReader::with_capacity(CHUNK, file), app, &in_path, total);
        let writer = BufWriter::with_capacity(CHUNK, File::create(&out_path)?);

        let opts = EncryptOptions {
            recipients: &recipients,
            signer: signer.as_ref(),
            passphrase: pass.as_ref().map(|p| p.as_str()),
            armor,
        };
        if let Err(e) = crypto::encrypt(reader, writer, &opts) {
            let _ = fs::remove_file(&out_path); // don't leave a truncated file
            return Err(e);
        }
        Ok(out_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(join_err)?;
    unlock.settle(&cache, sign_fp.as_deref(), result)
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    input_path: String,
    output_path: Option<String>,
    passphrase: Option<String>,
}

#[derive(Serialize)]
pub struct DecryptResult {
    output_path: String,
    signatures: Vec<SignatureStatus>,
}

#[tauri::command]
pub async fn decrypt_file(
    app: AppHandle,
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    request: DecryptRequest,
) -> Result<DecryptResult> {
    let certs = store.all()?;
    let pass = secret(request.passphrase);
    let cached = cache.snapshot();
    let in_path = PathBuf::from(&request.input_path);
    let out_path = request.output_path.map(PathBuf::from).unwrap_or_else(|| {
        let s = request.input_path.as_str();
        let stripped = [".gpg", ".asc", ".pgp"]
            .iter()
            .find_map(|ext| s.strip_suffix(ext))
            .filter(|b| !b.is_empty());
        unique(match stripped {
            Some(base) => PathBuf::from(base),
            None => default_output(s, "decrypted"),
        })
    });

    let (result, unlocked) = spawn_blocking(move || -> Result<(DecryptResult, Option<Unlocked>)> {
        let file = File::open(&in_path)?;
        let total = file.metadata()?.len();
        let reader = ProgressReader::new(BufReader::with_capacity(CHUNK, file), app, &in_path, total);
        let writer = BufWriter::with_capacity(CHUNK, File::create(&out_path)?);

        match crypto::decrypt(reader, writer, certs, pass.as_ref().map(|p| p.as_str()), cached) {
            Ok((signatures, unlocked)) => Ok((
                DecryptResult { output_path: out_path.to_string_lossy().into_owned(), signatures },
                unlocked,
            )),
            Err(e) => {
                let _ = fs::remove_file(&out_path);
                Err(e)
            }
        }
    })
    .await
    .map_err(join_err)??;
    if let Some(u) = unlocked {
        cache.store(&u.fingerprint, &u.passphrase);
    }
    Ok(result)
}

// ------------------------------------------------------------- text ----

#[tauri::command]
pub async fn encrypt_text(
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    text: String,
    recipients: Vec<String>,
    sign_with: Option<String>,
    passphrase: Option<String>,
) -> Result<String> {
    let text = Zeroizing::new(text);
    let recipients = recipients
        .iter()
        .map(|fp| store.get(fp).map_err(|_| GpgError::MissingRecipient(fp.clone())))
        .collect::<Result<Vec<_>>>()?;
    let signer = sign_with.as_deref().map(|fp| store.get(fp)).transpose()?;
    let unlock = Unlock::new(&cache, sign_with.as_deref(), passphrase);

    let mut out = Vec::new();
    let result = crypto::encrypt(
        Cursor::new(text.as_bytes()),
        &mut out,
        &EncryptOptions {
            recipients: &recipients,
            signer: signer.as_ref(),
            passphrase: unlock.as_str(),
            armor: true,
        },
    );
    unlock.settle(&cache, sign_with.as_deref(), result)?;
    String::from_utf8(out).map_err(|_| GpgError::Other("Encryption produced invalid text".into()))
}

#[derive(Serialize)]
pub struct TextDecryptResult {
    text: String,
    signatures: Vec<SignatureStatus>,
}

#[tauri::command]
pub async fn decrypt_text(
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    armored: String,
    passphrase: Option<String>,
) -> Result<TextDecryptResult> {
    let certs = store.all()?;
    let pass = secret(passphrase);
    let mut out = Vec::new();
    let (signatures, unlocked) = crypto::decrypt(
        Cursor::new(armored.into_bytes()),
        &mut out,
        certs,
        pass.as_ref().map(|p| p.as_str()),
        cache.snapshot(),
    )?;
    if let Some(u) = unlocked {
        cache.store(&u.fingerprint, &u.passphrase);
    }
    let text = String::from_utf8(out)
        .map_err(|_| GpgError::InvalidInput("Decrypted content is not valid UTF-8 text".into()))?;
    Ok(TextDecryptResult { text, signatures })
}

#[tauri::command]
pub async fn sign_text(
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    text: String,
    signer: String,
    passphrase: Option<String>,
) -> Result<String> {
    let text = Zeroizing::new(text);
    let cert = store.get(&signer)?;
    let unlock = Unlock::new(&cache, Some(&signer), passphrase);
    let result = crypto::sign_cleartext(text.as_bytes(), &cert, unlock.as_str());
    let signed = unlock.settle(&cache, Some(&signer), result)?;
    String::from_utf8(signed).map_err(|_| GpgError::Other("Signing produced invalid text".into()))
}

#[derive(Serialize)]
pub struct VerifyResult {
    text: String,
    signatures: Vec<SignatureStatus>,
}

#[tauri::command]
pub fn verify_text(store: State<'_, KeyStore>, signed: String) -> Result<VerifyResult> {
    let (text, signatures) = crypto::verify_cleartext(signed.as_bytes(), store.all()?)?;
    let text = String::from_utf8(text)
        .map_err(|_| GpgError::InvalidInput("The signed content is not valid UTF-8 text".into()))?;
    Ok(VerifyResult { text, signatures })
}

// ------------------------------------------------- contacts & trust ----

#[derive(Serialize)]
pub struct KeyDetail {
    info: KeyInfo,
    subkeys: Vec<SubkeyInfo>,
}

#[tauri::command]
pub fn key_detail(store: State<'_, KeyStore>, fingerprint: String) -> Result<KeyDetail> {
    let info = describe_one(&store, &fingerprint)?;
    let subkeys = keys::subkeys(&store.get(&fingerprint)?);
    Ok(KeyDetail { info, subkeys })
}

#[tauri::command]
pub fn set_ownertrust(
    store: State<'_, KeyStore>,
    fingerprint: String,
    level: Trust,
) -> Result<KeyInfo> {
    store.set_ownertrust(&fingerprint, level)?;
    describe_one(&store, &fingerprint)
}

#[tauri::command]
pub fn trust_graph(store: State<'_, KeyStore>) -> Result<Graph> {
    let certs = store.all()?;
    let owner = store.ownertrust_map(&certs);
    let edges = wot::certifications(&certs);
    let valid = wot::validity(&certs, &owner, &edges);
    Ok(wot::graph(&certs, &owner, &edges, &valid))
}

#[derive(Deserialize)]
pub struct CertifyRequest {
    target: String,
    signer: String,
    level: Level,
    user_ids: Vec<String>,
    passphrase: Option<String>,
}

#[tauri::command]
pub async fn certify_key(
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    request: CertifyRequest,
) -> Result<KeyInfo> {
    let target = store.get(&request.target)?;
    let signer = store.get(&request.signer)?;
    let unlock = Unlock::new(&cache, Some(&request.signer), request.passphrase);
    let level = request.level;
    let user_ids = request.user_ids;

    let pass = unlock.pass.clone();
    let result = spawn_blocking(move || {
        certify::certify(&target, &signer, level, &user_ids, pass.as_ref().map(|p| p.as_str()))
    })
    .await
    .map_err(join_err)?;
    let certified = unlock.settle(&cache, Some(&request.signer), result)?;

    let cert = store.put(certified)?;
    describe_one(&store, &cert.fingerprint().to_hex())
}

// ----------------------------------------------- revocation & backup ----

#[derive(Deserialize)]
pub struct RevokeRequest {
    fingerprint: String,
    reason: Reason,
    message: Option<String>,
    passphrase: Option<String>,
}

/// The key with a revocation signature added, signed with its own secret key.
fn revoked_cert(
    store: &KeyStore,
    cache: &PassphraseCache,
    request: RevokeRequest,
) -> Result<openpgp_cert::Cert> {
    let cert = store.get(&request.fingerprint)?;
    let unlock = Unlock::new(cache, Some(&request.fingerprint), request.passphrase);
    let result = revoke::revoke(&cert, request.reason, request.message.as_deref().unwrap_or(""), unlock.as_str());
    unlock.settle(cache, Some(&request.fingerprint), result)
}

/// A public key carrying its revocation: safe to keep anywhere and to publish.
/// Importing it later (here or elsewhere) revokes the key. Changes nothing now.
fn revocation_armor(cert: openpgp_cert::Cert) -> Result<Vec<u8>> {
    use sequoia_openpgp::serialize::SerializeInto;
    Ok(cert.strip_secret_key_material().armored().to_vec()?)
}

#[tauri::command]
pub fn revocation_certificate(
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    request: RevokeRequest,
) -> Result<String> {
    let bytes = revocation_armor(revoked_cert(&store, &cache, request)?)?;
    String::from_utf8(bytes).map_err(|_| GpgError::Other("Revocation produced invalid text".into()))
}

#[tauri::command]
pub fn save_revocation_certificate(
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    request: RevokeRequest,
    path: String,
) -> Result<()> {
    fs::write(path, revocation_armor(revoked_cert(&store, &cache, request)?)?)?;
    Ok(())
}

/// Revokes the key in this keyring. Publish it afterwards so others learn of it.
#[tauri::command]
pub fn revoke_key(
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    request: RevokeRequest,
) -> Result<KeyInfo> {
    let fingerprint = request.fingerprint.clone();
    let cert = revoked_cert(&store, &cache, request)?;
    store.put(cert)?;
    describe_one(&store, &fingerprint)
}

#[derive(Serialize)]
pub struct BackupReport {
    keys: usize,
    secret_keys: usize,
}

fn report(certs: &[openpgp_cert::Cert]) -> BackupReport {
    BackupReport { keys: certs.len(), secret_keys: certs.iter().filter(|c| c.is_tsk()).count() }
}

#[tauri::command]
pub fn create_backup(store: State<'_, KeyStore>, path: String, passphrase: String) -> Result<BackupReport> {
    let passphrase = Zeroizing::new(passphrase);
    let certs = store.all()?;
    let data = backup::create(&certs, &passphrase)?;
    crate::gpg::store::write_private(Path::new(&path), &data)?;
    Ok(report(&certs))
}

#[tauri::command]
pub fn restore_backup(store: State<'_, KeyStore>, path: String, passphrase: String) -> Result<BackupReport> {
    let passphrase = Zeroizing::new(passphrase);
    if fs::metadata(&path)?.len() > 64 * 1024 * 1024 {
        return Err(GpgError::InvalidInput("File is too large to be a backup".into()));
    }
    let certs = backup::restore(&fs::read(path)?, &passphrase)?;
    for cert in &certs {
        store.put(cert.clone())?;
    }
    Ok(report(&certs))
}

// ------------------------------------------------------ network ----

#[derive(Serialize)]
pub struct RemoteKey {
    info: KeyInfo,
    armored: String,
    already_have: bool,
}

fn remote_keys(store: &KeyStore, certs: Vec<sequoia_openpgp::Cert>) -> Result<Vec<RemoteKey>> {
    use sequoia_openpgp::serialize::SerializeInto;
    certs
        .into_iter()
        .map(|c| {
            let armored = String::from_utf8(c.armored().to_vec()?)
                .map_err(|_| GpgError::Other("Could not armor the key".into()))?;
            Ok(RemoteKey {
                already_have: store.get(&c.fingerprint().to_hex()).is_ok(),
                info: keys::info_unvalidated(&c),
                armored,
            })
        })
        .collect()
}

/// Looks the address up via WKD. Nothing is stored until the user imports.
#[tauri::command]
pub async fn lookup_wkd(store: State<'_, KeyStore>, email: String) -> Result<Vec<RemoteKey>> {
    remote_keys(&store, net::wkd(&email).await?)
}

#[tauri::command]
pub async fn lookup_keyserver(
    store: State<'_, KeyStore>,
    query: String,
    server: Server,
) -> Result<Vec<RemoteKey>> {
    remote_keys(&store, net::search(server, &query).await?)
}

#[tauri::command]
pub async fn upload_key(
    store: State<'_, KeyStore>,
    fingerprint: String,
    server: Server,
) -> Result<UploadReport> {
    // Only the public part ever leaves the machine (stripped in net::upload).
    let cert = store.get(&fingerprint)?;
    net::upload(server, &cert).await
}

#[derive(Serialize)]
pub struct RefreshChange {
    fingerprint: String,
    label: String,
    /// "revoked" | "updated"
    change: &'static str,
}

#[derive(Serialize)]
pub struct RefreshReport {
    checked: u32,
    unchanged: u32,
    not_found: u32,
    changes: Vec<RefreshChange>,
}

/// Re-fetches every key in the keyring and merges updates / revocations.
#[tauri::command]
pub async fn refresh_keys(store: State<'_, KeyStore>, server: Server) -> Result<RefreshReport> {
    let mut report = RefreshReport { checked: 0, unchanged: 0, not_found: 0, changes: Vec::new() };
    let mut consecutive_failures = 0;

    for before in store.all()? {
        let fp = before.fingerprint().to_hex();
        report.checked += 1;
        let remote = match net::fetch_by_fingerprint(server, &fp).await {
            Ok(r) => {
                consecutive_failures = 0;
                r
            }
            Err(e @ GpgError::Network(_)) => {
                consecutive_failures += 1;
                if consecutive_failures >= 3 {
                    return Err(e); // server unreachable: stop instead of waiting for every key
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        let Some(remote) = remote else {
            report.not_found += 1;
            continue;
        };

        let was_revoked = keys::info_unvalidated(&before).revoked;
        let after = store.put(remote)?;
        if after == before {
            report.unchanged += 1;
            continue;
        }
        let info = keys::info_unvalidated(&after);
        report.changes.push(RefreshChange {
            label: info.name.clone().or(info.email.clone()).unwrap_or_else(|| fp.clone()),
            change: if info.revoked && !was_revoked { "revoked" } else { "updated" },
            fingerprint: fp,
        });
    }
    Ok(report)
}

// ------------------------------------------------------------- QR ----

#[derive(Serialize)]
pub struct QrView {
    payload: String,
    svg: String,
    version: u8,
    ec: &'static str,
    bytes: usize,
}

#[tauri::command]
pub fn qr_code(store: State<'_, KeyStore>, fingerprint: String, mode: qr::Mode) -> Result<QrView> {
    let q = qr::build(&store.get(&fingerprint)?, mode)?;
    Ok(QrView {
        svg: qr::svg(&q.code),
        version: q.version(),
        ec: q.ec,
        bytes: q.payload.len(),
        payload: q.payload,
    })
}

/// Raw PNG bytes (sent as a binary IPC response, no JSON overhead).
#[tauri::command]
pub fn qr_png(
    store: State<'_, KeyStore>,
    fingerprint: String,
    mode: qr::Mode,
) -> Result<tauri::ipc::Response> {
    let q = qr::build(&store.get(&fingerprint)?, mode)?;
    Ok(tauri::ipc::Response::new(qr::png(&q.code)?))
}

/// Saves the QR code to a path chosen by the user; `.svg` → SVG, otherwise PNG.
#[tauri::command]
pub fn save_qr(
    store: State<'_, KeyStore>,
    fingerprint: String,
    mode: qr::Mode,
    path: String,
) -> Result<()> {
    let q = qr::build(&store.get(&fingerprint)?, mode)?;
    let is_svg = Path::new(&path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("svg"));
    if is_svg {
        fs::write(path, qr::svg(&q.code))?;
    } else {
        fs::write(path, qr::png(&q.code)?)?;
    }
    Ok(())
}

/// Imports a key from an `openpgp4fpr:` URI. The download is accepted only if
/// the returned key's fingerprint matches the scanned one exactly.
#[tauri::command]
pub async fn import_from_uri(
    store: State<'_, KeyStore>,
    uri: String,
    server: Server,
) -> Result<KeyInfo> {
    let fp = qr::parse_fingerprint_uri(&uri)?;
    let cert = net::fetch_by_fingerprint(server, &fp)
        .await?
        .ok_or_else(|| GpgError::NotFound(fp.clone()))?;
    store.put(cert)?;
    describe_one(&store, &fp)
}

// ------------------------------------------------ passphrase cache ----

/// Seconds to remember a typed passphrase; 0 turns the cache off.
#[tauri::command]
pub fn set_passphrase_ttl(cache: State<'_, PassphraseCache>, seconds: u64) {
    cache.set_ttl(seconds);
}

/// Panic button: forgets every remembered passphrase, empties the clipboard and quits.
/// Nothing else secret is kept in memory between operations.
#[tauri::command]
pub fn panic_wipe(app: AppHandle, cache: State<'_, PassphraseCache>) {
    cache.clear();
    crate::clipboard::clear_now();
    app.exit(0);
}

#[tauri::command]
pub fn clear_passphrase_cache(cache: State<'_, PassphraseCache>) {
    cache.clear();
}

// ------------------------------------------------------------ kleyknox ----

/// Whether a kleyknox vault is mounted, and which GPG keys it holds.
/// Scanning mounted volumes can stall on an unreachable network drive, so it
/// runs off the main thread (a plain `fn` command would run on it).
#[tauri::command]
pub async fn kleyknox_status() -> Result<kleyknox::Status> {
    spawn_blocking(kleyknox::status).await.map_err(join_err)
}

#[derive(Serialize)]
pub struct KleyKnoxReport {
    /// Keys whose passphrase is now remembered.
    pub unlocked: Vec<String>,
    /// Keys this keyring lacked, imported from the vault.
    pub imported: Vec<String>,
    /// Keys whose passphrase in the vault does not open the copy in this keyring.
    pub mismatched: Vec<String>,
}

/// Opens the kleyknox vault with its passphrase and remembers, for `ttl_seconds`,
/// the passphrase of every key it holds. Keys missing here are imported first.
#[tauri::command]
pub async fn kleyknox_unlock(
    store: State<'_, KeyStore>,
    cache: State<'_, PassphraseCache>,
    passphrase: String,
    ttl_seconds: u64,
) -> Result<KleyKnoxReport> {
    let pass = Zeroizing::new(passphrase);
    if pass.is_empty() {
        return Err(GpgError::PassphraseRequired);
    }
    let entries = spawn_blocking(move || {
        let dir = kleyknox::locate()
            .ok_or_else(|| GpgError::NotFound("a kleyknox vault on a mounted drive".into()))?;
        kleyknox::open_all(&dir, &pass)
    })
    .await
    .map_err(join_err)??;
    let ttl = Duration::from_secs(ttl_seconds.clamp(60, 24 * 3600));

    let mut report = KleyKnoxReport { unlocked: Vec::new(), imported: Vec::new(), mismatched: Vec::new() };
    for entry in entries {
        let cert = match store.get(&entry.fingerprint) {
            Ok(cert) if cert.is_tsk() => cert,
            _ => {
                let mut imported = None;
                for cert in keys::parse(entry.secret_armor.as_bytes())? {
                    if cert.fingerprint().to_hex() == entry.fingerprint {
                        imported = Some(store.put(cert)?);
                    }
                }
                let cert = imported.ok_or_else(|| {
                    GpgError::InvalidInput(format!("KleyKnox entry {} does not hold its key", entry.name))
                })?;
                report.imported.push(key_label(&cert, &entry.name));
                cert
            }
        };
        let label = key_label(&cert, &entry.name);
        match keys::check_passphrase(&cert, &entry.passphrase) {
            Ok(()) => {
                if !entry.passphrase.is_empty() {
                    cache.store_for(&entry.fingerprint, &entry.passphrase, ttl);
                }
                report.unlocked.push(label);
            }
            Err(GpgError::WrongPassphrase) => report.mismatched.push(label),
            Err(e) => return Err(e),
        }
    }
    Ok(report)
}

fn key_label(cert: &openpgp_cert::Cert, fallback: &str) -> String {
    cert.userids()
        .next()
        .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
        .unwrap_or_else(|| fallback.to_owned())
}
