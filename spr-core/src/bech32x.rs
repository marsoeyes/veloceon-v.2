//! Bech32 encoding (BIP173) used for SegWit and Cardano addresses.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.bytes() {
        out.push(c >> 5);
    }
    out.push(0);
    for c in hrp.bytes() {
        out.push(c & 31);
    }
    out
}

/// General 8 -> 5 bit regrouping with padding (as used by SegWit/Cardano).
pub fn convert_bits_to_5(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((data.len() * 8) / 5 + 2);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// Encode a bech32 string. `constant` is 1 for bech32 and 0x2bc830a3 for bech32m.
pub fn encode(hrp: &str, data5: &[u8], constant: u32) -> String {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data5);
    values.extend_from_slice(&[0u8; 6]);
    let pm = polymod(&values) ^ constant;
    let mut out = String::with_capacity(hrp.len() + 1 + data5.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for &d in data5 {
        out.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        let idx = ((pm >> (5 * (5 - i))) & 31) as usize;
        out.push(CHARSET[idx] as char);
    }
    out
}

/// BIP173 v0 SegWit address (P2WPKH / P2WSH).
pub fn segwit_v0(hrp: &str, program: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + program.len() * 8 / 5 + 1);
    data.push(0u8); // witness version 0
    data.extend_from_slice(&convert_bits_to_5(program));
    encode(hrp, &data, 1)
}

/// Raw bech32 payload encoding (Cardano addresses).
pub fn encode_bytes(hrp: &str, payload: &[u8]) -> String {
    encode(hrp, &convert_bits_to_5(payload), 1)
}
