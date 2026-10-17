//! Address encoders for every supported network.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::bech32x;

pub const RIPPLE_ALPHABET: &[u8; 58] =
    b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let s = sha256(data);
    let d = Ripemd160::digest(s);
    let mut out = [0u8; 20];
    out.copy_from_slice(&d);
    out
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let d = Keccak256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Base58Check with the Bitcoin alphabet.
pub fn base58check(version: u8, payload: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(payload.len() + 5);
    bytes.push(version);
    bytes.extend_from_slice(payload);
    let checksum = sha256d(&bytes);
    bytes.extend_from_slice(&checksum[..4]);
    bs58::encode(bytes).into_string()
}

/// Ripple's base58 alphabet variant.
pub fn ripple_base58check(payload: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(payload.len() + 4);
    bytes.extend_from_slice(payload);
    let checksum = sha256d(&bytes);
    bytes.extend_from_slice(&checksum[..4]);
    let alphabet = bs58::Alphabet::new(RIPPLE_ALPHABET).expect("58 symbols");
    bs58::encode(bytes)
        .with_alphabet(&alphabet)
        .into_string()
}

/// 0x-prefixed EIP-55 checksummed EVM address.
pub fn evm_address(uncompressed: &[u8; 65]) -> String {
    let hash = keccak256(&uncompressed[1..]);
    let body = hex::encode(&hash[12..]);
    let checksum = keccak256(body.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in body.chars().enumerate() {
        let nibble = if i % 2 == 0 {
            checksum[i / 2] >> 4
        } else {
            checksum[i / 2] & 0x0f
        };
        if ch.is_ascii_alphabetic() && nibble >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Lower-case EVM address (for matching).
pub fn evm_address_lower(uncompressed: &[u8; 65]) -> String {
    let hash = keccak256(&uncompressed[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

pub fn tron_address(uncompressed: &[u8; 65]) -> String {
    let hash = keccak256(&uncompressed[1..]);
    base58check(0x41, &hash[12..])
}

pub fn xrp_address(compressed_pub: &[u8; 33]) -> String {
    let account_id = hash160(compressed_pub);
    let mut payload = [0u8; 21];
    payload[0] = 0x00;
    payload[1..].copy_from_slice(&account_id);
    ripple_base58check(&payload)
}

pub fn doge_address(compressed_pub: &[u8; 33]) -> String {
    base58check(0x1e, &hash160(compressed_pub))
}

pub fn btc_p2pkh(compressed_pub: &[u8; 33]) -> String {
    base58check(0x00, &hash160(compressed_pub))
}

pub fn btc_p2sh_p2wpkh(compressed_pub: &[u8; 33]) -> String {
    let key_hash = hash160(compressed_pub);
    let mut redeem = [0u8; 22];
    redeem[0] = 0x00;
    redeem[1] = 0x14;
    redeem[2..].copy_from_slice(&key_hash);
    base58check(0x05, &hash160(&redeem))
}

pub fn btc_p2wpkh(compressed_pub: &[u8; 33]) -> String {
    bech32x::segwit_v0("bc", &hash160(compressed_pub))
}

pub fn solana_address(pubkey: &[u8; 32]) -> String {
    bs58::encode(pubkey).into_string()
}

/// Shelley base address (type 0): header, payment key hash, stake key hash.
pub fn cardano_base_address(network_id: u8, payment: &[u8; 28], stake: &[u8; 28]) -> String {
    let mut payload = [0u8; 57];
    payload[0] = (0u8 << 4) | (network_id & 0x0f);
    payload[1..29].copy_from_slice(payment);
    payload[29..57].copy_from_slice(stake);
    let hrp = if network_id == 1 { "addr" } else { "addr_test" };
    bech32x::encode_bytes(hrp, &payload)
}

pub fn cardano_reward_address(network_id: u8, stake: &[u8; 28]) -> String {
    let mut payload = [0u8; 29];
    payload[0] = (0x0eu8 << 4) | (network_id & 0x0f);
    payload[1..].copy_from_slice(stake);
    let hrp = if network_id == 1 {
        "stake"
    } else {
        "stake_test"
    };
    bech32x::encode_bytes(hrp, &payload)
}
