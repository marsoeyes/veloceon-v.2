//! Minimal BIP32 (secp256k1) implementation.

use hmac::{Hmac, KeyInit, Mac};
use secp256k1::{PublicKey, Scalar, SecretKey};
use sha2::Sha512;

pub const HARDENED: u32 = 0x8000_0000;

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&out);
    buf
}

#[derive(Clone)]
pub struct ExtKey {
    pub key: SecretKey,
    pub chain: [u8; 32],
}

fn secret_from_slice(bytes: &[u8; 32]) -> Option<SecretKey> {
    SecretKey::from_secret_bytes(*bytes).ok()
}

pub fn master(seed: &[u8]) -> Option<ExtKey> {
    let i = hmac_sha512(b"Bitcoin seed", seed);
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&i[..32]);
    let key = secret_from_slice(&key_bytes)?;
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&i[32..]);
    Some(ExtKey { key, chain })
}

impl ExtKey {
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_secret_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.key)
    }

    /// CKDpriv. Returns `None` for the (vanishingly unlikely) invalid-tweak case.
    pub fn child(&self, index: u32) -> Option<ExtKey> {
        let mut data = [0u8; 37];
        if index & HARDENED != 0 {
            data[0] = 0;
            data[1..33].copy_from_slice(&self.key.to_secret_bytes());
        } else {
            let pk = self.public_key().serialize();
            data[..33].copy_from_slice(&pk);
        }
        data[33..37].copy_from_slice(&index.to_be_bytes());

        let i = hmac_sha512(&self.chain, &data);
        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let tweak = Scalar::from_be_bytes(il).ok()?;
        let key = self.key.add_tweak(&tweak).ok()?;
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&i[32..]);
        Some(ExtKey { key, chain })
    }
}

/// Parse `m/44'/60'/0'/0/0` (also accepts `44'/60'...` without the leading `m`).
pub fn parse_path(path: &str) -> crate::Result<Vec<u32>> {
    let cleaned = path.trim();
    let cleaned = cleaned.strip_prefix("m/").unwrap_or(cleaned);
    let cleaned = cleaned.strip_prefix("m").unwrap_or(cleaned);
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for part in cleaned.split('/') {
        let part = part.trim();
        if part.is_empty() {
            return Err(crate::Error::BadPath(path.to_string()));
        }
        let (digits, hardened) = match part.strip_suffix('\'').or_else(|| part.strip_suffix('h')) {
            Some(d) => (d, true),
            None => (part, false),
        };
        let raw: u32 = digits
            .parse()
            .map_err(|_| crate::Error::BadPath(path.to_string()))?;
        if raw >= HARDENED {
            return Err(crate::Error::BadPath(path.to_string()));
        }
        out.push(if hardened { raw | HARDENED } else { raw });
    }
    Ok(out)
}

pub fn derive_path(root: &ExtKey, path: &[u32]) -> Option<ExtKey> {
    let mut cur = root.clone();
    for &idx in path {
        cur = cur.child(idx)?;
    }
    Some(cur)
}
