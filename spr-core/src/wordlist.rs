use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// BIP39 languages supported by the recovery engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    English,
    Spanish,
    French,
    Italian,
    Portuguese,
    Czech,
    Korean,
    Japanese,
    ChineseSimplified,
    ChineseTraditional,
}

impl Language {
    pub const ALL: [Language; 10] = [
        Language::English,
        Language::Spanish,
        Language::French,
        Language::Italian,
        Language::Portuguese,
        Language::Czech,
        Language::Korean,
        Language::Japanese,
        Language::ChineseSimplified,
        Language::ChineseTraditional,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Language::English => "english",
            Language::Spanish => "spanish",
            Language::French => "french",
            Language::Italian => "italian",
            Language::Portuguese => "portuguese",
            Language::Czech => "czech",
            Language::Korean => "korean",
            Language::Japanese => "japanese",
            Language::ChineseSimplified => "chinese-simplified",
            Language::ChineseTraditional => "chinese-traditional",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        let s = s.replace('_', "-");
        Some(match s.as_str() {
            "en" | "english" => Language::English,
            "es" | "spanish" => Language::Spanish,
            "fr" | "french" => Language::French,
            "it" | "italian" => Language::Italian,
            "pt" | "portuguese" => Language::Portuguese,
            "cs" | "czech" => Language::Czech,
            "ko" | "korean" => Language::Korean,
            "ja" | "jp" | "japanese" => Language::Japanese,
            "zh" | "zh-cn" | "chinese" | "chinese-simplified" | "simplified-chinese" => {
                Language::ChineseSimplified
            }
            "zh-tw" | "chinese-traditional" | "traditional-chinese" => {
                Language::ChineseTraditional
            }
            _ => return None,
        })
    }

    fn bip39(self) -> bip39::Language {
        match self {
            Language::English => bip39::Language::English,
            Language::Spanish => bip39::Language::Spanish,
            Language::French => bip39::Language::French,
            Language::Italian => bip39::Language::Italian,
            Language::Portuguese => bip39::Language::Portuguese,
            Language::Czech => bip39::Language::Czech,
            Language::Korean => bip39::Language::Korean,
            Language::Japanese => bip39::Language::Japanese,
            Language::ChineseSimplified => bip39::Language::SimplifiedChinese,
            Language::ChineseTraditional => bip39::Language::TraditionalChinese,
        }
    }

    /// BIP39 Japanese mnemonics are joined with an ideographic space.
    pub fn separator(self) -> &'static str {
        match self {
            Language::Japanese => "\u{3000}",
            _ => " ",
        }
    }
}

impl std::str::FromStr for Language {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        Language::parse(s).ok_or_else(|| {
            let available: Vec<&str> = Language::ALL.iter().map(|l| l.code()).collect();
            crate::Error::Msg(format!(
                "unknown wordlist {s:?}; available: {}",
                available.join(", ")
            ))
        })
    }
}

/// A resolved BIP39 wordlist plus an index for fast reverse lookups.
pub struct WordList {
    pub language: Language,
    words: &'static [&'static str; 2048],
    index: HashMap<&'static str, u16>,
}

impl WordList {
    pub fn new(language: Language) -> Self {
        let words = language.bip39().word_list();
        let mut index = HashMap::with_capacity(2048);
        for (i, w) in words.iter().enumerate() {
            index.insert(*w, i as u16);
        }
        Self {
            language,
            words,
            index,
        }
    }

    #[inline]
    pub fn words(&self) -> &'static [&'static str; 2048] {
        self.words
    }

    #[inline]
    pub fn word(&self, idx: u16) -> &'static str {
        self.words[idx as usize]
    }

    /// Case-insensitive, whitespace tolerant lookup.
    pub fn index_of(&self, word: &str) -> Option<u16> {
        let w = word.trim();
        if let Some(i) = self.index.get(w) {
            return Some(*i);
        }
        let lower = w.to_ascii_lowercase();
        self.index.get(lower.as_str()).copied()
    }

    pub fn contains(&self, word: &str) -> bool {
        self.index_of(word).is_some()
    }
}
