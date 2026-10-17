//! Network list, derivation-path configuration and prepared derivations.

use serde::{Deserialize, Serialize};

use crate::bip32::{self, HARDENED};
use crate::{addr, cardano, slip10, Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Evm,
    Btc,
    Doge,
    Xrp,
    Tron,
    Solana,
    Cardano,
}

impl Network {
    pub const ALL: [Network; 7] = [
        Network::Evm,
        Network::Btc,
        Network::Doge,
        Network::Xrp,
        Network::Tron,
        Network::Solana,
        Network::Cardano,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Network::Evm => "evm",
            Network::Btc => "btc",
            Network::Doge => "doge",
            Network::Xrp => "xrp",
            Network::Tron => "tron",
            Network::Solana => "solana",
            Network::Cardano => "cardano",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Network::Evm => "EVM",
            Network::Btc => "Bitcoin",
            Network::Doge => "Dogecoin",
            Network::Xrp => "Ripple XRP",
            Network::Tron => "Tron",
            Network::Solana => "Solana",
            Network::Cardano => "Cardano",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "evm" | "eth" | "ethereum" | "bsc" | "bnb" | "polygon" | "arbitrum" | "base" => {
                Network::Evm
            }
            "btc" | "bitcoin" => Network::Btc,
            "doge" | "dogecoin" => Network::Doge,
            "xrp" | "ripple" => Network::Xrp,
            "trx" | "tron" => Network::Tron,
            "sol" | "solana" => Network::Solana,
            "ada" | "cardano" => Network::Cardano,
            _ => return None,
        })
    }

    /// Human readable prefix hint used by the dashboard.
    pub fn address_hint(self) -> &'static str {
        match self {
            Network::Evm => "0x...",
            Network::Btc => "bc1... / 1... / 3...",
            Network::Doge => "D...",
            Network::Xrp => "r...",
            Network::Tron => "T...",
            Network::Solana => "base58 (32-44)",
            Network::Cardano => "addr1...",
        }
    }
}

impl std::str::FromStr for Network {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Network::parse(s).ok_or_else(|| {
            Error::Msg(format!(
                "unknown network {s:?}; available: evm, btc, doge, xrp, tron, solana, cardano"
            ))
        })
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddrKind {
    Evm,
    BtcP2pkh,
    BtcP2shP2wpkh,
    BtcP2wpkh,
    Doge,
    Xrp,
    Tron,
}

impl AddrKind {
    pub fn for_network(network: Network) -> Option<Self> {
        Some(match network {
            Network::Evm => AddrKind::Evm,
            Network::Btc => AddrKind::BtcP2pkh,
            Network::Doge => AddrKind::Doge,
            Network::Xrp => AddrKind::Xrp,
            Network::Tron => AddrKind::Tron,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DerivationSpec {
    Bip32 {
        network: Network,
        path: String,
        base: Vec<u32>,
        leaf: Option<u32>,
        kind: AddrKind,
    },
    Slip10 {
        network: Network,
        path: String,
        base: Vec<u32>,
    },
    Cardano {
        path: String,
        account: u32,
        index: u32,
        network_id: u8,
    },
}

impl DerivationSpec {
    pub fn network(&self) -> Network {
        match self {
            DerivationSpec::Bip32 { network, .. } => *network,
            DerivationSpec::Slip10 { network, .. } => *network,
            DerivationSpec::Cardano { .. } => Network::Cardano,
        }
    }

    pub fn path(&self) -> &str {
        match self {
            DerivationSpec::Bip32 { path, .. }
            | DerivationSpec::Slip10 { path, .. }
            | DerivationSpec::Cardano { path, .. } => path,
        }
    }

    pub fn label(&self) -> String {
        format!("{} · {}", self.network().as_str(), self.path())
    }
}

fn split_leaf(mut parts: Vec<u32>) -> (Vec<u32>, Option<u32>) {
    if let Some(&last) = parts.last() {
        if last & HARDENED == 0 {
            parts.pop();
            return (parts, Some(last));
        }
    }
    (parts, None)
}

pub fn bip32_spec(network: Network, path: &str, kind: AddrKind) -> Result<DerivationSpec> {
    let parts = bip32::parse_path(path)?;
    let (base, leaf) = split_leaf(parts);
    Ok(DerivationSpec::Bip32 {
        network,
        path: path.to_string(),
        base,
        leaf,
        kind,
    })
}

pub fn slip10_spec(network: Network, path: &str) -> Result<DerivationSpec> {
    let parts = bip32::parse_path(path)?;
    if parts.iter().any(|p| p & HARDENED == 0) {
        return Err(Error::BadPath(format!(
            "{path}: ed25519 (SLIP-0010) only supports hardened indices, e.g. m/44'/501'/0'/0'"
        )));
    }
    Ok(DerivationSpec::Slip10 {
        network,
        path: path.to_string(),
        base: parts,
    })
}

pub fn cardano_spec(path: &str, network_id: u8) -> Result<DerivationSpec> {
    let parts = bip32::parse_path(path)?;
    if parts.len() < 5 {
        return Err(Error::BadPath(format!(
            "{path}: Cardano needs at least m/1852'/1815'/account'/role/index"
        )));
    }
    let account = parts[2] & !HARDENED;
    let index = parts[parts.len() - 1] & !HARDENED;
    Ok(DerivationSpec::Cardano {
        path: path.to_string(),
        account,
        index,
        network_id,
    })
}

/// Build a spec from a user supplied path string.
pub fn spec_from_path(network: Network, path: &str) -> Result<DerivationSpec> {
    match network {
        Network::Solana => slip10_spec(network, path),
        Network::Cardano => cardano_spec(path, 1),
        _ => {
            let kind = AddrKind::for_network(network)
                .ok_or_else(|| Error::Msg(format!("{network} has no path based addresses")))?;
            bip32_spec(network, path, kind)
        }
    }
}

/// Standard derivation paths for a network.
pub fn default_derivations(network: Network, breadth: u32) -> Vec<DerivationSpec> {
    let breadth = breadth.clamp(1, 20);
    let mut out = Vec::new();
    match network {
        Network::Evm => {
            for i in 0..breadth {
                out.push(
                    bip32_spec(Network::Evm, &format!("m/44'/60'/0'/0/{i}"), AddrKind::Evm)
                        .expect("static path"),
                );
            }
            // Legacy MEV/mist style path used by a few old wallets.
            out.push(
                bip32_spec(Network::Evm, "m/44'/60'/0'/0/0", AddrKind::Evm).expect("static path"),
            );
        }
        Network::Btc => {
            for i in 0..breadth {
                out.push(
                    bip32_spec(Network::Btc, &format!("m/44'/0'/0'/0/{i}"), AddrKind::BtcP2pkh)
                        .expect("static path"),
                );
                out.push(
                    bip32_spec(Network::Btc, &format!("m/49'/0'/0'/0/{i}"), AddrKind::BtcP2shP2wpkh)
                        .expect("static path"),
                );
                out.push(
                    bip32_spec(Network::Btc, &format!("m/84'/0'/0'/0/{i}"), AddrKind::BtcP2wpkh)
                        .expect("static path"),
                );
            }
        }
        Network::Doge => {
            for i in 0..breadth {
                out.push(
                    bip32_spec(Network::Doge, &format!("m/44'/3'/0'/0/{i}"), AddrKind::Doge)
                        .expect("static path"),
                );
            }
        }
        Network::Xrp => {
            for i in 0..breadth {
                out.push(
                    bip32_spec(Network::Xrp, &format!("m/44'/144'/0'/0/{i}"), AddrKind::Xrp)
                        .expect("static path"),
                );
            }
        }
        Network::Tron => {
            for i in 0..breadth {
                out.push(
                    bip32_spec(Network::Tron, &format!("m/44'/195'/0'/0/{i}"), AddrKind::Tron)
                        .expect("static path"),
                );
            }
        }
        Network::Solana => {
            out.push(
                slip10_spec(Network::Solana, "m/44'/501'/0'/0'").expect("static path"),
            );
            if breadth > 1 {
                out.push(slip10_spec(Network::Solana, "m/44'/501'/0'").expect("static path"));
            }
        }
        Network::Cardano => {
            for i in 0..breadth {
                out.push(
                    cardano_spec(&format!("m/1852'/1815'/0'/0/{i}"), 1).expect("static path"),
                );
            }
        }
    }
    out.dedup_by(|a, b| a.path() == b.path() && a.network() == b.network());
    out
}

struct Bip32Item {
    network: Network,
    path: String,
    leaf: Option<u32>,
    kind: AddrKind,
}

enum Group {
    Bip32 {
        base: Vec<u32>,
        items: Vec<Bip32Item>,
    },
    Slip10 {
        base: Vec<u32>,
        items: Vec<(Network, String)>,
    },
    Cardano {
        account: u32,
        network_id: u8,
        items: Vec<(Network, String, u32)>,
    },
}

/// Derivations grouped so shared path prefixes are only walked once per seed.
pub struct PreparedDerivations {
    groups: Vec<Group>,
    count: usize,
}

fn find_bip32_group(groups: &mut Vec<Group>, base: &[u32]) -> usize {
    for (i, g) in groups.iter().enumerate() {
        if let Group::Bip32 { base: b, .. } = g {
            if b.as_slice() == base {
                return i;
            }
        }
    }
    groups.push(Group::Bip32 {
        base: base.to_vec(),
        items: Vec::new(),
    });
    groups.len() - 1
}

impl PreparedDerivations {
    pub fn new(specs: &[DerivationSpec], filter: &[Network]) -> Self {
        let active = |n: Network| filter.is_empty() || filter.contains(&n);
        let mut groups: Vec<Group> = Vec::new();
        let mut count = 0usize;

        for spec in specs {
            match spec {
                DerivationSpec::Bip32 {
                    network,
                    path,
                    base,
                    leaf,
                    kind,
                } => {
                    if !active(*network) {
                        continue;
                    }
                    let idx = find_bip32_group(&mut groups, base);
                    if let Group::Bip32 { items, .. } = &mut groups[idx] {
                        items.push(Bip32Item {
                            network: *network,
                            path: path.clone(),
                            leaf: *leaf,
                            kind: *kind,
                        });
                        count += 1;
                    }
                }
                DerivationSpec::Slip10 { network, path, base } => {
                    if !active(*network) {
                        continue;
                    }
                    if let Some(Group::Slip10 { items, .. }) = groups
                        .iter_mut()
                        .find(|g| matches!(g, Group::Slip10 { base: b, .. } if b == base))
                    {
                        items.push((*network, path.clone()));
                    } else {
                        groups.push(Group::Slip10 {
                            base: base.clone(),
                            items: vec![(*network, path.clone())],
                        });
                    }
                    count += 1;
                }
                DerivationSpec::Cardano {
                    path,
                    account,
                    index,
                    network_id,
                } => {
                    if !active(Network::Cardano) {
                        continue;
                    }
                    if let Some(Group::Cardano { items, .. }) = groups
                        .iter_mut()
                        .find(|g| matches!(g, Group::Cardano { account: a, .. } if a == account))
                    {
                        items.push((Network::Cardano, path.clone(), *index));
                    } else {
                        groups.push(Group::Cardano {
                            account: *account,
                            network_id: *network_id,
                            items: vec![(Network::Cardano, path.clone(), *index)],
                        });
                    }
                    count += 1;
                }
            }
        }
        Self { groups, count }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Derive every configured address for one seed.
    pub fn evaluate(
        &self,
        seed: &[u8; 64],
        entropy: &[u8],
        passphrase: &str,
        f: &mut dyn FnMut(Network, &str, String),
    ) {
        for group in &self.groups {
            match group {
                Group::Bip32 { base, items } => {
                    let Some(root) = bip32::master(seed) else {
                        continue;
                    };
                    let Some(parent) = bip32::derive_path(&root, base) else {
                        continue;
                    };
                    for item in items {
                        let key = match item.leaf {
                            Some(i) => match parent.child(i) {
                                Some(k) => k,
                                None => continue,
                            },
                            None => parent.clone(),
                        };
                        let pk = key.public_key();
                        let address = match item.kind {
                            AddrKind::Evm => {
                                addr::evm_address(&pk.serialize_uncompressed())
                            }
                            AddrKind::Tron => {
                                addr::tron_address(&pk.serialize_uncompressed())
                            }
                            AddrKind::BtcP2pkh => addr::btc_p2pkh(&pk.serialize()),
                            AddrKind::BtcP2shP2wpkh => {
                                addr::btc_p2sh_p2wpkh(&pk.serialize())
                            }
                            AddrKind::BtcP2wpkh => addr::btc_p2wpkh(&pk.serialize()),
                            AddrKind::Doge => addr::doge_address(&pk.serialize()),
                            AddrKind::Xrp => addr::xrp_address(&pk.serialize()),
                        };
                        f(item.network, &item.path, address);
                    }
                }
                Group::Slip10 { base, items } => {
                    let root = slip10::master(seed);
                    let mut key = root;
                    for &i in base {
                        key = key.child_hardened(i);
                    }
                    let pubkey = key.public_key();
                    let address = addr::solana_address(&pubkey);
                    for (network, path) in items {
                        f(*network, path, address.clone());
                    }
                }
                Group::Cardano {
                    account,
                    network_id,
                    items,
                } => {
                    let master = cardano::icarus_master(entropy, passphrase.as_bytes());
                    let account_key = master
                        .child_hardened(1852)
                        .child_hardened(1815)
                        .child_hardened(*account);
                    let stake_key = account_key.child_hardened(2).child_hardened(0);
                    let stake_hash = cardano::blake2b224(&stake_key.public_key());
                    for (network, path, index) in items {
                        let payment_key = account_key.child_hardened(0).child_hardened(*index);
                        let payment_hash = cardano::blake2b224(&payment_key.public_key());
                        let address = addr::cardano_base_address(
                            *network_id,
                            &payment_hash,
                            &stake_hash,
                        );
                        f(*network, path, address);
                    }
                }
            }
        }
    }
}
