/// One of the purposes contained in the [extended key usage extension](https://tools.ietf.org/html/rfc5280#section-4.2.1.12)
/// flutter_rust_bridge:non_opaque
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum ExtendedKeyUsagePurpose {
    /// anyExtendedKeyUsage
    Any,
    /// id-kp-serverAuth
    ServerAuth,
    /// id-kp-clientAuth
    ClientAuth,
    /// id-kp-codeSigning
    CodeSigning,
    /// id-kp-emailProtection
    EmailProtection,
    /// id-kp-timeStamping
    TimeStamping,
    /// id-kp-OCSPSigning
    OcspSigning,
    /// A custom purpose not from the pre-specified list of purposes
    Other(Vec<u64>),
}

impl From<ExtendedKeyUsagePurpose> for rcgen::ExtendedKeyUsagePurpose {
    fn from(value: ExtendedKeyUsagePurpose) -> Self {
        match value {
            ExtendedKeyUsagePurpose::Any => Self::Any,
            ExtendedKeyUsagePurpose::ServerAuth => Self::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth => Self::ClientAuth,
            ExtendedKeyUsagePurpose::CodeSigning => Self::CodeSigning,
            ExtendedKeyUsagePurpose::EmailProtection => Self::EmailProtection,
            ExtendedKeyUsagePurpose::TimeStamping => Self::TimeStamping,
            ExtendedKeyUsagePurpose::OcspSigning => Self::OcspSigning,
            ExtendedKeyUsagePurpose::Other(items) => Self::Other(items),
        }
    }
}
