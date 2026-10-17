//! PBKDF2-HMAC-SHA512 tuned for BIP39 / Icarus seed stretching.
//!
//! A textbook HMAC re-hashes the 128-byte ipad/opad blocks on every call. Since
//! PBKDF2 runs the same password 2048 (BIP39) or 4096 (Icarus) times, we
//! compress the two pad blocks once and reuse the resulting chaining states,
//! halving the number of SHA-512 compressions per iteration.

use sha2::block_api::compress512;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[inline]
fn hash_from_state(mut state: [u64; 8], prefix_len: usize, msg: &[u8]) -> [u8; 64] {
    let total = msg.len() + 1 + 16;
    let nblocks = total.div_ceil(128);
    let bitlen = ((prefix_len + msg.len()) as u128 * 8).to_be_bytes();

    if nblocks <= 2 {
        let mut blocks = [[0u8; 128]; 2];
        for (i, chunk) in msg.chunks(128).enumerate() {
            blocks[i][..chunk.len()].copy_from_slice(chunk);
        }
        blocks[msg.len() / 128][msg.len() % 128] = 0x80;
        blocks[nblocks - 1][112..128].copy_from_slice(&bitlen);
        compress512(&mut state, &blocks[..nblocks]);
    } else {
        let mut blocks = vec![[0u8; 128]; nblocks];
        for (i, chunk) in msg.chunks(128).enumerate() {
            blocks[i][..chunk.len()].copy_from_slice(chunk);
        }
        blocks[msg.len() / 128][msg.len() % 128] = 0x80;
        blocks[nblocks - 1][112..128].copy_from_slice(&bitlen);
        compress512(&mut state, &blocks);
    }

    let mut out = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC-SHA512 with precomputed key schedule.
#[derive(Clone)]
pub struct HmacSha512 {
    inner: [u64; 8],
    outer: [u64; 8],
}

impl HmacSha512 {
    pub fn new(key: &[u8]) -> Self {
        let mut block = [0u8; 128];
        if key.len() > 128 {
            use sha2::{Digest, Sha512};
            let d = Sha512::digest(key);
            block[..64].copy_from_slice(&d);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0u8; 128];
        let mut opad = [0u8; 128];
        for i in 0..128 {
            ipad[i] = block[i] ^ 0x36;
            opad[i] = block[i] ^ 0x5c;
        }
        let mut inner = IV;
        compress512(&mut inner, &[ipad]);
        let mut outer = IV;
        compress512(&mut outer, &[opad]);
        Self { inner, outer }
    }

    #[inline]
    pub fn mac(&self, msg: &[u8]) -> [u8; 64] {
        let inner_digest = hash_from_state(self.inner, 128, msg);
        hash_from_state(self.outer, 128, &inner_digest)
    }
}

/// PBKDF2-HMAC-SHA512 (RFC 8018) writing `out.len()` bytes (multiple of 64 not required).
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    debug_assert!(iterations >= 1);
    let prf = HmacSha512::new(password);
    let mut offset = 0;
    let mut block_index: u32 = 1;
    let mut first_msg = Vec::with_capacity(salt.len() + 4);
    while offset < out.len() {
        first_msg.clear();
        first_msg.extend_from_slice(salt);
        first_msg.extend_from_slice(&block_index.to_be_bytes());

        let mut u = prf.mac(&first_msg);
        let mut t = u;
        for _ in 1..iterations {
            u = prf.mac(&u);
            for i in 0..64 {
                t[i] ^= u[i];
            }
        }
        let take = (out.len() - offset).min(64);
        out[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        block_index += 1;
    }
}

/// SHA-512 convenience wrapper.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let d = Sha512::digest(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&d);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc4231_hmac_sha512() {
        // RFC 4231 test case 1
        let prf = HmacSha512::new(&[0x0b; 20]);
        let out = prf.mac(b"Hi There");
        assert_eq!(
            hex(&out),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn long_key_hmac_sha512() {
        // RFC 4231 test case 6 (key longer than block size)
        let prf = HmacSha512::new(&[0xaa; 131]);
        let out = prf.mac(b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            hex(&out),
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        );
    }

    #[test]
    fn pbkdf2_multi_block() {
        // 96 bytes forces two PBKDF2 output blocks. Reference value computed with
        // Python's hashlib.pbkdf2_hmac (independent implementation).
        let mut out = [0u8; 96];
        pbkdf2_sha512(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            hex(&out),
            "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5d6883f0be4c24d363b638f4c2f8d917533cd4158937d0b490697a64adadb07f1"
        );
    }
}
