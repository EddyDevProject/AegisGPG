use serde::{ser::SerializeStruct, Serialize, Serializer};
use sequoia_openpgp as openpgp;

pub type Result<T> = std::result::Result<T, GpgError>;

#[derive(Debug, thiserror::Error)]
pub enum GpgError {
    #[error("Passphrase incorrect")]
    WrongPassphrase,
    #[error("A passphrase is required to unlock this key")]
    PassphraseRequired,
    #[error("Missing public key for recipient {0}")]
    MissingRecipient(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("No matching secret key is available to decrypt this message")]
    NoSecretKey,
    #[error("The selected key cannot sign (no secret signing key)")]
    NoSigningKey,
    #[error("Select at least one recipient or enable signing")]
    NothingToDo,
    #[error("File corrupted or not a valid OpenPGP message")]
    Corrupted,
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    Network(String),
    #[error("Key too large for a single QR code: show the keyserver URL or the fingerprint instead")]
    QrTooLarge,
    #[error("No key found for {0}")]
    NotFound(String),
    #[error("File error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl GpgError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::WrongPassphrase => "wrong_passphrase",
            Self::PassphraseRequired => "passphrase_required",
            Self::MissingRecipient(_) => "missing_recipient",
            Self::KeyNotFound(_) => "key_not_found",
            Self::NoSecretKey => "no_secret_key",
            Self::NoSigningKey => "no_signing_key",
            Self::NothingToDo => "nothing_to_do",
            Self::Corrupted => "corrupted",
            Self::InvalidInput(_) => "invalid_input",
            Self::Network(_) => "network",
            Self::NotFound(_) => "not_found",
            Self::QrTooLarge => "qr_too_large",
            Self::Io(_) => "io",
            Self::Other(_) => "other",
        }
    }
}

impl From<anyhow::Error> for GpgError {
    fn from(e: anyhow::Error) -> Self {
        // Errors raised inside sequoia callbacks travel as anyhow::Error.
        let e = match e.downcast::<GpgError>() {
            Ok(g) => return g,
            Err(e) => e,
        };
        let e = match e.downcast::<std::io::Error>() {
            Ok(io) => return GpgError::Io(io),
            Err(e) => e,
        };
        match e.downcast_ref::<openpgp::Error>() {
            Some(
                openpgp::Error::MalformedMessage(_)
                | openpgp::Error::MalformedPacket(_)
                | openpgp::Error::ManipulatedMessage
                | openpgp::Error::MalformedMPI(_),
            ) => GpgError::Corrupted,
            _ => GpgError::Other(format!("{e:#}")),
        }
    }
}

/// Serialised as `{ code, message }` so the frontend can branch on `code`.
impl Serialize for GpgError {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("GpgError", 2)?;
        st.serialize_field("code", self.code())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}
