//! Target addresses (the addresses you already know) and matching rules.

use serde::{Deserialize, Serialize};

use crate::deriv::Network;
use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    /// Whole address equality.
    Exact,
    /// Candidate starts with the given fragment.
    Prefix,
    /// Candidate ends with the given fragment.
    Suffix,
    /// Candidate contains the given fragment.
    Contains,
}

impl MatchMode {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "exact" | "eq" | "equals" => MatchMode::Exact,
            "prefix" | "starts" | "starts-with" => MatchMode::Prefix,
            "suffix" | "ends" | "ends-with" => MatchMode::Suffix,
            "contains" | "partial" => MatchMode::Contains,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MatchMode::Exact => "exact",
            MatchMode::Prefix => "prefix",
            MatchMode::Suffix => "suffix",
            MatchMode::Contains => "contains",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    pub network: Network,
    pub value: String,
    pub mode: MatchMode,
}

impl Target {
    pub fn new(network: Network, value: impl Into<String>, mode: MatchMode) -> Self {
        let value = value.into();
        let value = normalize(network, &value);
        Self {
            network,
            value,
            mode,
        }
    }

    /// Accepts `net:address`, or a bare address when `default_network` is set.
    pub fn parse(spec: &str, default_network: Option<Network>) -> Result<Self, Error> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(Error::Msg("empty target address".into()));
        }
        let looks_like_evm = spec.starts_with("0x") || spec.starts_with("0X");
        let (network, value) = if let Some((prefix, rest)) = spec.split_once(':') {
            match Network::parse(prefix) {
                Some(n) => (n, rest.trim().to_string()),
                None if prefix.eq_ignore_ascii_case("wallet") => {
                    let net = default_network.ok_or_else(|| {
                        Error::Msg(format!("target {spec:?} needs a network, e.g. evm:{rest}"))
                    })?;
                    (net, rest.trim().to_string())
                }
                None => {
                    // Not a network prefix: treat the whole string as the address.
                    let net = default_network.unwrap_or_else(|| {
                        if looks_like_evm {
                            Network::Evm
                        } else {
                            Network::Btc
                        }
                    });
                    (net, spec.to_string())
                }
            }
        } else {
            let net = default_network.unwrap_or_else(|| {
                if looks_like_evm {
                    Network::Evm
                } else {
                    Network::Btc
                }
            });
            (net, spec.to_string())
        };
        if value.is_empty() {
            return Err(Error::Msg(format!("target {spec:?} has no address")));
        }
        Ok(Target::new(network, value, MatchMode::Exact))
    }

    pub fn with_mode(mut self, mode: MatchMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn matches(&self, network: Network, address: &str) -> bool {
        if network != self.network {
            return false;
        }
        let candidate = normalize(network, address);
        match self.mode {
            MatchMode::Exact => candidate == self.value,
            MatchMode::Prefix => candidate.starts_with(&self.value),
            MatchMode::Suffix => candidate.ends_with(&self.value),
            MatchMode::Contains => candidate.contains(&self.value),
        }
    }
}

/// Network aware normalisation so users can paste addresses with or without `0x`/checksums.
pub fn normalize(network: Network, addr: &str) -> String {
    let trimmed = addr.trim();
    match network {
        Network::Evm => {
            let body = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
                .unwrap_or(trimmed);
            body.to_ascii_lowercase()
        }
        Network::Cardano => trimmed.to_ascii_lowercase(),
        Network::Btc
            if trimmed.len() > 4
                && (trimmed.to_ascii_lowercase().starts_with("bc1")
                    || trimmed.to_ascii_lowercase().starts_with("tb1")) =>
        {
            trimmed.to_ascii_lowercase()
        }
        _ => trimmed.to_string(),
    }
}
