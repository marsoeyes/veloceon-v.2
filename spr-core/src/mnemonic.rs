//! BIP39 bit packing, checksum filtering and seed stretching.

use sha2::{Digest, Sha256};

use crate::hmac_fast::pbkdf2_sha512;

pub const WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub words: usize,
    /// Checksum bits (4 for 12 words ... 8 for 24 words).
    pub cs_bits: usize,
    pub ent_bytes: usize,
}

impl Layout {
    pub fn new(words: usize) -> Option<Self> {
        if !WORD_COUNTS.contains(&words) {
            return None;
        }
        let bits = words * 11;
        let cs_bits = bits / 33;
        Some(Self {
            words,
            cs_bits,
            ent_bytes: (bits - cs_bits) / 8,
        })
    }
}

/// Pack the entropy portion of an 11-bit index sequence into bytes.
#[inline]
pub fn extract_entropy(indices: &[u16], layout: &Layout, out: &mut [u8; 32]) {
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    let mut o = 0usize;
    for &idx in indices {
        acc = (acc << 11) | idx as u64;
        nbits += 11;
        while nbits >= 8 {
            nbits -= 8;
            out[o] = ((acc >> nbits) & 0xff) as u8;
            o += 1;
            if o == layout.ent_bytes {
                return;
            }
        }
    }
}

/// Validate the BIP39 checksum for a full index vector.
#[inline]
pub fn checksum_ok(indices: &[u16], layout: &Layout) -> bool {
    let mut entropy = [0u8; 32];
    extract_entropy(indices, layout, &mut entropy);
    let digest = Sha256::digest(&entropy[..layout.ent_bytes]);
    let expected = (digest[0] >> (8 - layout.cs_bits)) as u16;
    let mask = (1u16 << layout.cs_bits) - 1;
    (indices[layout.words - 1] & mask) == expected
}

/// BIP39 seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048, 64).
pub fn seed_from_phrase(phrase: &str, passphrase: &str) -> [u8; 64] {
    let mut salt = Vec::with_capacity(8 + passphrase.len());
    salt.extend_from_slice(b"mnemonic");
    salt.extend_from_slice(passphrase.as_bytes());
    let mut seed = [0u8; 64];
    pbkdf2_sha512(phrase.as_bytes(), &salt, 2048, &mut seed);
    seed
}

pub fn needs_normalization(s: &str) -> bool {
    !s.is_ascii()
}

pub fn nfkd(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    s.nfkd().collect()
}

/// Split a phrase the way a user might type it (any whitespace, `?`/`*`/`_` for unknown).
pub fn split_template(input: &str) -> Vec<Option<String>> {
    input
        .split_whitespace()
        .map(|w| {
            let trimmed = w.trim_matches(|c: char| c == ',' || c == '.');
            if trimmed == "?"
                || trimmed == "??"
                || trimmed == "*"
                || trimmed == "_"
                || trimmed == "x"
                || trimmed == "X"
                || trimmed == "-"
            {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_values() {
        for n in WORD_COUNTS {
            let l = Layout::new(n).unwrap();
            assert_eq!(l.ent_bytes * 8, n * 11 - l.cs_bits);
        }
        assert!(Layout::new(13).is_none());
    }

    #[test]
    fn all_abandon_checksum() {
        let layout = Layout::new(12).unwrap();
        let mut idx = [0u16; 12];
        idx[11] = 3; // "about"
        assert!(checksum_ok(&idx, &layout));
        idx[11] = 4;
        assert!(!checksum_ok(&idx, &layout));
    }

    #[test]
    fn template_parsing() {
        let t = split_template("abandon ? * _ about");
        assert_eq!(t.len(), 5);
        assert!(t[0].is_some());
        assert!(t[1].is_none());
        assert!(t[4].is_some());
    }
}
