//! Published / independently verified test vectors used by `spr selfcheck` so a
//! user can confirm the build they run behaves exactly like the reference
//! wallets (BIP39, BIP32, BIP49, BIP84, SLIP-0010, CIP-3/CIP-1852, BIP173).
//!
//! Every value below was cross-checked against `bip_utils` 2.12 (an independent
//! implementation) and, where one exists, against the official specification
//! vector.

use std::sync::Arc;

use serde::Serialize;

use crate::deriv::{default_derivations, Network};
use crate::{
    addr, bech32x, bip32, cardano as cardano_mod, engine, mnemonic, slip10, SearchConfig, Target,
};

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub expected: String,
    pub actual: String,
}

impl Check {
    fn new(name: &str, expected: impl Into<String>, actual: impl Into<String>) -> Self {
        let expected = expected.into();
        let actual = actual.into();
        let ok = expected == actual;
        Self {
            name: name.to_string(),
            ok,
            expected,
            actual,
        }
    }
}

/// The standard BIP39 test mnemonic ("abandon" x11 + "about").
pub const ABANDON_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub const ETH_0: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn entropy_of(phrase: &str) -> Vec<u8> {
    let m = bip39::Mnemonic::parse_in(bip39::Language::English, phrase).expect("valid phrase");
    m.to_entropy()
}

/// Cryptographic derivation checks (fast, no search).
pub fn crypto_checks() -> Vec<Check> {
    let mut out = Vec::new();

    // -- BIP39 -------------------------------------------------------------
    let seed = mnemonic::seed_from_phrase(ABANDON_12, "");
    out.push(Check::new(
        "BIP39 seed (abandon x11 + about)",
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        hex(&seed),
    ));

    let root = bip32::master(&seed).expect("valid master key");
    let derive = |path: &str| {
        bip32::derive_path(&root, &bip32::parse_path(path).unwrap()).expect("valid path")
    };

    // -- secp256k1 chains --------------------------------------------------
    out.push(Check::new(
        "Bitcoin BIP44 m/44'/0'/0'/0/0 (P2PKH)",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        addr::btc_p2pkh(&derive("m/44'/0'/0'/0/0").public_key().serialize()),
    ));
    out.push(Check::new(
        "Bitcoin BIP49 m/49'/0'/0'/0/0 (P2SH-P2WPKH)",
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        addr::btc_p2sh_p2wpkh(&derive("m/49'/0'/0'/0/0").public_key().serialize()),
    ));
    out.push(Check::new(
        "Bitcoin BIP84 m/84'/0'/0'/0/0 (P2WPKH)",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        addr::btc_p2wpkh(&derive("m/84'/0'/0'/0/0").public_key().serialize()),
    ));
    out.push(Check::new(
        "Ethereum/EVM m/44'/60'/0'/0/0",
        ETH_0,
        addr::evm_address(&derive("m/44'/60'/0'/0/0").public_key().serialize_uncompressed()),
    ));
    out.push(Check::new(
        "Dogecoin m/44'/3'/0'/0/0",
        "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC",
        addr::doge_address(&derive("m/44'/3'/0'/0/0").public_key().serialize()),
    ));
    out.push(Check::new(
        "Ripple XRP m/44'/144'/0'/0/0",
        "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3",
        addr::xrp_address(&derive("m/44'/144'/0'/0/0").public_key().serialize()),
    ));
    out.push(Check::new(
        "Tron m/44'/195'/0'/0/0",
        "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
        addr::tron_address(&derive("m/44'/195'/0'/0/0").public_key().serialize_uncompressed()),
    ));

    // -- SLIP-0010 ed25519 / Solana ---------------------------------------
    let slip_seed: Vec<u8> = (0u8..16).collect();
    let slip_master = slip10::master(&slip_seed);
    out.push(Check::new(
        "SLIP-0010 ed25519 master private key",
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
        hex(&slip_master.key),
    ));
    out.push(Check::new(
        "SLIP-0010 ed25519 master chain code",
        "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
        hex(&slip_master.chain),
    ));
    out.push(Check::new(
        "SLIP-0010 ed25519 master public key",
        "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
        hex(&slip_master.public_key()),
    ));
    let slip_m0 = slip_master.child_hardened(0);
    out.push(Check::new(
        "SLIP-0010 ed25519 m/0' private key",
        "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
        hex(&slip_m0.key),
    ));

    let mut sol = slip10::master(&seed);
    for i in bip32::parse_path("m/44'/501'/0'/0'").unwrap() {
        sol = sol.child_hardened(i);
    }
    out.push(Check::new(
        "Solana m/44'/501'/0'/0'",
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        addr::solana_address(&sol.public_key()),
    ));

    // -- Cardano (Icarus / CIP-3 + CIP-1852) ------------------------------
    let cip3_phrase =
        "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
    let cip3_master = cardano_mod::icarus_master(&entropy_of(cip3_phrase), b"");
    let mut cip3_bytes = Vec::with_capacity(96);
    cip3_bytes.extend_from_slice(&cip3_master.k);
    cip3_bytes.extend_from_slice(&cip3_master.c);
    out.push(Check::new(
        "Cardano CIP-3 Icarus master key",
        "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620",
        hex(&cip3_bytes),
    ));

    let ada_master = cardano_mod::icarus_master(&entropy_of(ABANDON_12), b"");
    let ada_account = ada_master
        .child_hardened(1852)
        .child_hardened(1815)
        .child_hardened(0);
    let ada_pay = ada_account.child_hardened(0).child_hardened(0);
    let ada_stake = ada_account.child_hardened(2).child_hardened(0);
    let ada_pay_pub = ada_pay.public_key();
    let ada_stake_pub = ada_stake.public_key();
    out.push(Check::new(
        "Cardano payment key m/1852'/1815'/0'/0/0",
        "ba91ad7e08d4dd6600d1fa7eaf38378635e862ffaa92e477e18943f3f046a3f6",
        hex(&ada_pay_pub),
    ));
    out.push(Check::new(
        "Cardano stake key m/1852'/1815'/0'/2/0",
        "95f76d01f5b6cd7c3ae021383bc19e4ecb6d8460506750d36f8071db3e795659",
        hex(&ada_stake_pub),
    ));
    out.push(Check::new(
        "Cardano Shelley base address (mainnet)",
        "addr1q8ra05numl23sglhml9aja7jfnad8l2jt0mvcj4ewrwvgzyp7cpg8eu9xfj5mqmj9eu5jzsm77pmvh83wetw0qtvaxlswuus8u",
        addr::cardano_base_address(
            1,
            &cardano_mod::blake2b224(&ada_pay_pub),
            &cardano_mod::blake2b224(&ada_stake_pub),
        ),
    ));

    // -- BIP173 bech32 -----------------------------------------------------
    let program = hex_decode("751e76e8199196d454941c45d1b3a323f1433bd6");
    out.push(Check::new(
        "BIP173 P2WPKH bech32",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        bech32x::segwit_v0("bc", &program),
    ));

    out
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// End-to-end recovery: the last word of the test mnemonic is unknown and the
/// only way to find it is deriving the known EVM address.
pub fn engine_check() -> Check {
    let mut template: Vec<Option<String>> = ABANDON_12
        .split_whitespace()
        .map(|w| Some(w.to_string()))
        .collect();
    template[11] = None;

    let cfg = SearchConfig {
        language: crate::Language::English,
        template,
        position_candidates: Vec::new(),
        passphrase: String::new(),
        derivations: default_derivations(Network::Evm, 1),
        targets: vec![Target::new(
            Network::Evm,
            ETH_0,
            crate::MatchMode::Exact,
        )],
    };

    let plan = match engine::build_plan(&cfg) {
        Ok(p) => p,
        Err(e) => return Check::new("engine recovery (1 missing word)", "found", e.to_string()),
    };
    let progress = Arc::new(crate::Progress::new(plan.total, 2, true, 1));
    if let Err(e) = engine::run(Arc::new(plan), progress.clone()) {
        return Check::new("engine recovery (1 missing word)", "found", e.to_string());
    }
    match progress.hits().first() {
        Some(h) => Check::new(
            "engine recovery (1 missing word)",
            ABANDON_12,
            h.phrase.clone(),
        ),
        None => Check::new(
            "engine recovery (1 missing word)",
            ABANDON_12,
            "no match found".to_string(),
        ),
    }
}

pub fn all_checks(include_engine: bool) -> Vec<Check> {
    let mut checks = crypto_checks();
    if include_engine {
        checks.push(engine_check());
    }
    checks
}
