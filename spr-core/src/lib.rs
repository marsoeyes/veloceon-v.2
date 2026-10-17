//! `spr-core` — offline seed phrase recovery engine.
//!
//! Recovery works by enumerating candidate mnemonics around the words you
//! already know, filtering them with the BIP39 checksum, then deriving the
//! wallet addresses for every configured network/derivation path and comparing
//! them against the addresses *you* supply as targets.
//!
//! Nothing leaves the machine and no network requests are made: the only way a
//! candidate is ever reported is by matching a target address you provided.

pub mod addr;
pub mod bech32x;
pub mod bip32;
pub mod cardano;
pub mod deriv;
pub mod engine;
pub mod error;
pub mod hmac_fast;
pub mod mnemonic;
pub mod slip10;
pub mod target;
pub mod vectors;
pub mod wordlist;

pub use deriv::{AddrKind, DerivationSpec, Network};
pub use engine::{
    build_plan, derive_all, run, run_range, Hit, Progress, SearchConfig, SearchPlan, Snapshot,
    MAX_MISSING_WORDS,
};
pub use error::{Error, Result};
pub use target::{MatchMode, Target};
pub use wordlist::{Language, WordList};

/// Version of the recovery engine, surfaced in the CLI and the dashboard.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
