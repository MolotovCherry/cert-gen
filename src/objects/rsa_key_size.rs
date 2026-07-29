#[allow(non_camel_case_types)]
#[cfg(feature = "extra_signature_algos")]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RsaKeySize {
    /// 2048 bits
    k2048,
    /// 3072 bits
    k3072,
    /// 4096 bits
    k4096,
}

#[cfg(feature = "extra_signature_algos")]
impl From<RsaKeySize> for rcgen::RsaKeySize {
    fn from(value: RsaKeySize) -> Self {
        match value {
            RsaKeySize::k2048 => Self::_2048,
            RsaKeySize::k3072 => Self::_3072,
            RsaKeySize::k4096 => Self::_4096,
        }
    }
}
