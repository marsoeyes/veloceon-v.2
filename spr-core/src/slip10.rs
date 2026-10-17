//! SLIP-0010 ed25519 derivation (hardened only), used by Solana.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::hmac_fast::sha512;

#[derive(Clone)]
pub struct EdExtKey {
    pub key: [u8; 32],
    pub chain: [u8; 32],
}

/// SLIP-0010 ed25519 master key. Note the spec applies **no** bit clamping here;
/// the 32 bytes become the private key verbatim.
pub fn master(seed: &[u8]) -> EdExtKey {
    let i = hmac(b"ed25519 seed", seed);
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&i[..32]);
    chain.copy_from_slice(&i[32..]);
    EdExtKey { key, chain }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 64] {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha512;
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&out);
    buf
}

impl EdExtKey {
    /// SLIP-0010 ed25519 only supports hardened indices. The child private key is
    /// the left half of the HMAC output directly (ed25519 has no key addition step).
    pub fn child_hardened(&self, index: u32) -> EdExtKey {
        let mut data = [0u8; 37];
        data[0] = 0;
        data[1..33].copy_from_slice(&self.key);
        let idx = index | 0x8000_0000;
        data[33..37].copy_from_slice(&idx.to_be_bytes());
        let i = hmac(&self.chain, &data);

        let mut key = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&i[32..]);
        EdExtKey { key, chain }
    }

    pub fn child(&self, index: u32) -> Option<EdExtKey> {
        if index & 0x8000_0000 == 0 {
            None
        } else {
            Some(self.child_hardened(index))
        }
    }

    /// Ed25519 public key. SLIP-0010 defines the child key as a 32 byte seed which
    /// is expanded with SHA-512 and clamped, exactly like RFC 8032 key generation
    /// (this is what every Solana wallet does with the derived key).
    pub fn public_key(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        s.copy_from_slice(&sha512(&self.key)[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(s))
            .compress()
            .to_bytes()
    }
}
