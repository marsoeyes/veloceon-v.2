//! Cardano (Icarus / CIP-3) master key plus BIP32-Ed25519 V2 child derivation.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::hmac_fast::pbkdf2_sha512;

#[derive(Clone)]
pub struct CardanoKey {
    /// Extended private key: kL || kR
    pub k: [u8; 64],
    pub c: [u8; 32],
}

/// Icarus master key: PBKDF2-HMAC-SHA512(password=passphrase, salt=entropy, 4096, 96 bytes).
pub fn icarus_master(entropy: &[u8], passphrase: &[u8]) -> CardanoKey {
    let mut out = [0u8; 96];
    pbkdf2_sha512(passphrase, entropy, 4096, &mut out);
    out[0] &= 0b1111_1000;
    out[31] &= 0b0001_1111;
    out[31] |= 0b0100_0000;
    CardanoKey::from_parts(&out)
}

impl CardanoKey {
    fn from_parts(data: &[u8; 96]) -> Self {
        let mut k = [0u8; 64];
        let mut c = [0u8; 32];
        k.copy_from_slice(&data[..64]);
        c.copy_from_slice(&data[64..]);
        Self { k, c }
    }

    /// V2 (hardened) child derivation shared by wallet implementations.
    pub fn child_hardened(&self, index: u32) -> CardanoKey {
        let idx = (index | 0x8000_0000).to_le_bytes();
        let mut data = [0u8; 1 + 64 + 4];
        data[0] = 0x00;
        data[1..65].copy_from_slice(&self.k);
        data[65..69].copy_from_slice(&idx);
        let z = crate::bip32::hmac_sha512(&self.c, &data);

        data[0] = 0x01;
        let i = crate::bip32::hmac_sha512(&self.c, &data);

        let mut kl = [0u8; 32];
        kl.copy_from_slice(&self.k[..32]);
        let mut kr = [0u8; 32];
        kr.copy_from_slice(&self.k[32..]);

        // kL' = kL + 8 * trunc28(zL)  (mod 2^256)
        // 8 * trunc28(ZL), little-endian limbs
        let mut adj = [0u8; 32];
        let mut carry = 0u16;
        for j in 0..28 {
            let v = (z[j] as u16) << 3 | carry;
            adj[j] = v as u8;
            carry = v >> 8;
        }
        adj[28] = carry as u8;

        let kl = add_le(&kl, &adj);

        // kR' = kR + zR (mod 2^256)
        let mut zr = [0u8; 32];
        zr.copy_from_slice(&z[32..]);
        let kr = add_le(&kr, &zr);

        let mut k = [0u8; 64];
        k[..32].copy_from_slice(&kl);
        k[32..].copy_from_slice(&kr);
        let mut c = [0u8; 32];
        c.copy_from_slice(&i[32..]);
        Self { k, c }
    }

    pub fn public_key(&self) -> [u8; 32] {
        let mut kl = [0u8; 32];
        kl.copy_from_slice(&self.k[..32]);
        EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(kl))
            .compress()
            .to_bytes()
    }

    pub fn derive_path(&self, path: &[u32]) -> CardanoKey {
        let mut cur = self.clone();
        for &i in path {
            cur = cur.child_hardened(i);
        }
        cur
    }
}

/// 256-bit addition over little-endian limb arrays (BIP32-Ed25519 scalars are LE).
fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = a[i] as u16 + b[i] as u16 + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    out
}

/// Blake2b-224, used for Cardano key hashes.
pub fn blake2b224(data: &[u8]) -> [u8; 28] {
    use blake2::digest::consts::U28;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U28>::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 28];
    out.copy_from_slice(&digest);
    out
}

