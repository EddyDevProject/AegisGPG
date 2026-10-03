//! OpenPGP services built on `sequoia-openpgp` (pure-Rust backend).

pub mod certify;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod net;
pub mod qr;
pub mod store;
pub mod wot;

pub use error::{GpgError, Result};
