//! OpenPGP services built on `sequoia-openpgp` (pure-Rust backend).

pub mod backup;
pub mod certify;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod net;
pub mod passphrase_cache;
pub mod qr;
pub mod revoke;
pub mod store;
pub mod teams;
pub mod vault;
pub mod wot;

pub use error::{GpgError, Result};
