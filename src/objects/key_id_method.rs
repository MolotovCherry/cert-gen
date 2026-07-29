/// flutter_rust_bridge:non_opaque
#[derive(Debug, PartialEq, Eq, Hash, Clone, Default)]
pub enum KeyIdMethod {
    /// RFC 7093 method 1 - a truncated SHA256 digest.
    #[default]
    Sha256,
    /// RFC 7093 method 2 - a truncated SHA384 digest.
    Sha384,
    /// RFC 7093 method 3 - a truncated SHA512 digest.
    Sha512,
    /// Pre-specified identifier. The exact given value is used as the key identifier.
    PreSpecified(Vec<u8>),
}

impl From<KeyIdMethod> for rcgen::KeyIdMethod {
    fn from(value: KeyIdMethod) -> Self {
        match value {
            KeyIdMethod::Sha256 => Self::Sha256,
            KeyIdMethod::Sha384 => Self::Sha384,
            KeyIdMethod::Sha512 => Self::Sha512,
            KeyIdMethod::PreSpecified(items) => Self::PreSpecified(items),
        }
    }
}
