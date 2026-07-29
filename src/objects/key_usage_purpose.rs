#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum KeyUsagePurpose {
    /// digitalSignature
    DigitalSignature,
    /// contentCommitment / nonRepudiation
    ContentCommitment,
    /// keyEncipherment
    KeyEncipherment,
    /// dataEncipherment
    DataEncipherment,
    /// keyAgreement
    KeyAgreement,
    /// keyCertSign
    KeyCertSign,
    /// cRLSign
    CrlSign,
    /// encipherOnly
    EncipherOnly,
    /// decipherOnly
    DecipherOnly,
}

impl From<KeyUsagePurpose> for rcgen::KeyUsagePurpose {
    fn from(value: KeyUsagePurpose) -> Self {
        match value {
            KeyUsagePurpose::DigitalSignature => Self::DigitalSignature,
            KeyUsagePurpose::ContentCommitment => Self::ContentCommitment,
            KeyUsagePurpose::KeyEncipherment => Self::KeyEncipherment,
            KeyUsagePurpose::DataEncipherment => Self::DataEncipherment,
            KeyUsagePurpose::KeyAgreement => Self::KeyAgreement,
            KeyUsagePurpose::KeyCertSign => Self::KeyCertSign,
            KeyUsagePurpose::CrlSign => Self::CrlSign,
            KeyUsagePurpose::EncipherOnly => Self::EncipherOnly,
            KeyUsagePurpose::DecipherOnly => Self::DecipherOnly,
        }
    }
}
