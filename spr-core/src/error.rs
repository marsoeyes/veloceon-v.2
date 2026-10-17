use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Human readable validation/configuration error.
    Msg(String),
    /// Word count not one of 12/15/18/21/24.
    WordCount(usize),
    /// Unknown word for the selected BIP39 wordlist.
    UnknownWord { position: usize, word: String },
    /// Too many unknown words for a brute force search.
    TooManyMissing(usize),
    /// A derivation path could not be parsed.
    BadPath(String),
    /// No targets / no derivations configured.
    Empty(String),
    /// Underlying crypto primitive failed (astronomically unlikely).
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Msg(m) => write!(f, "{m}"),
            Error::WordCount(n) => write!(
                f,
                "invalid phrase length: {n} words (expected 12, 15, 18, 21 or 24)"
            ),
            Error::UnknownWord { position, word } => {
                write!(f, "word {position} ({word:?}) is not in the selected wordlist")
            }
            Error::TooManyMissing(n) => write!(
                f,
                "{n} unknown words is too many for a deterministic search (max 3); \
                 fill in at least {} words",
                n.saturating_sub(3)
            ),
            Error::BadPath(p) => write!(f, "invalid derivation path: {p}"),
            Error::Empty(m) => write!(f, "{m}"),
            Error::Crypto(m) => write!(f, "crypto failure: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Msg(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Msg(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
