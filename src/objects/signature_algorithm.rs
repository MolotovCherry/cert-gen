#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub enum SignatureAlgorithm {
    #[cfg(feature = "extra_signature_algos")]
    RSA_SHA256,
    #[cfg(feature = "extra_signature_algos")]
    RSA_SHA384,
    #[cfg(feature = "extra_signature_algos")]
    RSA_SHA512,
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    #[cfg(feature = "extra_signature_algos")]
    ECDSA_P521_SHA256,
    #[cfg(feature = "extra_signature_algos")]
    ECDSA_P521_SHA384,
    #[cfg(feature = "extra_signature_algos")]
    ECDSA_P521_SHA512,
    #[default]
    ED25519,
    #[cfg(feature = "extra_signature_algos")]
    ML_DSA_44,
    #[cfg(feature = "extra_signature_algos")]
    ML_DSA_65,
    #[cfg(feature = "extra_signature_algos")]
    ML_DSA_87,
}

impl SignatureAlgorithm {
    pub(crate) fn is_rsa(&self) -> bool {
        #[cfg(feature = "extra_signature_algos")]
        {
            matches!(self, Self::RSA_SHA256 | Self::RSA_SHA384 | Self::RSA_SHA512)
        }

        #[cfg(not(feature = "extra_signature_algos"))]
        {
            false
        }
    }
}

impl From<SignatureAlgorithm> for &'static rcgen::SignatureAlgorithm {
    fn from(value: SignatureAlgorithm) -> Self {
        match value {
            #[cfg(feature = "extra_signature_algos")]
            SignatureAlgorithm::RSA_SHA256 => &rcgen::PKCS_RSA_SHA256,
            #[cfg(feature = "extra_signature_algos")]
            SignatureAlgorithm::RSA_SHA384 => &rcgen::PKCS_RSA_SHA384,
            #[cfg(feature = "extra_signature_algos")]
            SignatureAlgorithm::RSA_SHA512 => &rcgen::PKCS_RSA_SHA512,
            SignatureAlgorithm::ECDSA_P256_SHA256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            SignatureAlgorithm::ECDSA_P384_SHA384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            #[cfg(feature = "extra_signature_algos")]
            SignatureAlgorithm::ECDSA_P521_SHA256 => &rcgen::PKCS_ECDSA_P521_SHA256,
            #[cfg(feature = "extra_signature_algos")]
            SignatureAlgorithm::ECDSA_P521_SHA384 => &rcgen::PKCS_ECDSA_P521_SHA384,
            #[cfg(feature = "extra_signature_algos")]
            SignatureAlgorithm::ECDSA_P521_SHA512 => &rcgen::PKCS_ECDSA_P521_SHA512,
            SignatureAlgorithm::ED25519 => &rcgen::PKCS_ED25519,
            #[cfg(feature = "extra_signature_algos")]
            SignatureAlgorithm::ML_DSA_44 => &rcgen::PKCS_ML_DSA_44,
            #[cfg(feature = "extra_signature_algos")]
            SignatureAlgorithm::ML_DSA_65 => &rcgen::PKCS_ML_DSA_65,
            #[cfg(feature = "extra_signature_algos")]
            SignatureAlgorithm::ML_DSA_87 => &rcgen::PKCS_ML_DSA_87,
        }
    }
}
