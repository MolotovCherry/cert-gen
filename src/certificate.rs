use bon::Builder;
pub use rcgen::{BasicConstraints, IsCa};

use crate::objects::{
    CertifiedKey, CrlDistributionPoint, CustomExtension, Date, DnType, ExtendedKeyUsagePurpose,
    KeyIdMethod, KeyUsagePurpose, RsaKeySize, SerialNumber, SignatureAlgorithm,
};
use certificate_builder::{
    IsComplete, IsUnset, SetDistinguishedName, SetNotAfter, SetNotBefore, SetSubjectAltNames, State,
};

#[derive(Debug, thiserror::Error)]
pub enum CertificateErr {
    #[error("{0}")]
    GenErr(#[from] rcgen::Error),
    #[error("rsa keysize required when using rsa sig algo")]
    RsaKeySizeNotSet,
    #[error("failed to guess the ca cert type")]
    CaCertTypeErr,
}

#[derive(Debug, Builder)]
#[builder(finish_fn(vis = ""))] // internal builder
pub struct Certificate {
    /// Optional CA to use instead of making our own.
    /// This is full public CA file contents (not a path).
    /// It can be a normal PEM string, or DER bytes
    /// flutter_rust_bridge:non_final
    #[builder(into)]
    pub ca_cert: Option<Vec<u8>>,
    /// Optional CA to use instead of making our own.
    /// This is full private CA file contents (not a path).
    /// It can be a normal PEM string, or DER bytes
    /// flutter_rust_bridge:non_final
    #[builder(into)]
    pub ca_key: Option<Vec<u8>>,
    #[builder(default = IsCa::NoCa)]
    pub is_ca: IsCa,
    /// Signature algorithm for the CSR. If not set, defaults to PKCS_ED25519.
    /// If you select RSA, you must set `rsa_key_size` as well.
    /// flutter_rust_bridge:non_final
    #[builder(default)]
    pub signature: SignatureAlgorithm,
    /// Certificate starting date. Use [`date_time_ymd`] to generate a date
    /// flutter_rust_bridge:non_final
    #[builder(setters(vis = "", name = not_before_internal))]
    pub not_before: Date,
    /// Certificate ending date. Use [`date_time_ymd`] to generate a date
    /// flutter_rust_bridge:non_final
    #[builder(setters(vis = "", name = not_after_internal))]
    pub not_after: Date,
    /// flutter_rust_bridge:non_final
    #[builder(setters(vis = "", name = subject_alt_names_internal))]
    pub subject_alt_names: Vec<String>,
    /// flutter_rust_bridge:non_final
    pub serial_number: Option<SerialNumber>,
    /// flutter_rust_bridge:non_final
    #[builder(setters(vis = "", name = distinguished_name_internal))]
    pub distinguished_name: Vec<(DnType, String)>,
    /// flutter_rust_bridge:non_final
    #[builder(into)]
    pub key_usages: Vec<KeyUsagePurpose>,
    /// flutter_rust_bridge:non_final
    #[builder(into)]
    pub extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
    /// An optional list of certificate revocation list (CRL) distribution points as described
    /// in RFC 5280 Section 4.2.1.13[^1]. Each distribution point contains one or more URIs where
    /// an up-to-date CRL with scope including this certificate can be retrieved.
    ///
    /// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13>
    /// flutter_rust_bridge:non_final
    #[builder(default)]
    #[builder(into)]
    pub crl_distribution_points: Vec<CrlDistributionPoint>,
    /// flutter_rust_bridge:non_final
    #[builder(default)]
    #[builder(into)]
    pub custom_extensions: Vec<CustomExtension>,
    /// flutter_rust_bridge:non_final
    #[builder(default)]
    /// If `true`, the ‘Authority Key Identifier’ extension will be added to the generated cert
    /// flutter_rust_bridge:non_final
    pub use_authority_key_identifier_extension: bool,
    /// Method to generate key identifiers from public keys
    ///
    /// Defaults to a truncated SHA-256 digest. See [`KeyIdMethod`] for more information.
    /// flutter_rust_bridge:non_final
    #[builder(default)]
    pub key_identifier_method: KeyIdMethod,
    /// The key size used for RSA key generation
    /// flutter_rust_bridge:non_final
    #[cfg(feature = "extra_signature_algos")]
    #[builder(into)]
    pub rsa_key_size: Option<RsaKeySize>,
}

impl Default for Certificate {
    fn default() -> Self {
        Self {
            not_before: Date {
                year: 1975,
                month: 1,
                day: 1,
            },
            not_after: Date {
                year: 4096,
                month: 1,
                day: 1,
            },
            ca_cert: None,
            ca_key: None,
            is_ca: IsCa::NoCa,
            signature: Default::default(),
            subject_alt_names: Default::default(),
            serial_number: Default::default(),
            distinguished_name: Default::default(),
            key_usages: Default::default(),
            extended_key_usages: Default::default(),
            crl_distribution_points: Default::default(),
            custom_extensions: Default::default(),
            use_authority_key_identifier_extension: Default::default(),
            key_identifier_method: Default::default(),
            rsa_key_size: Default::default(),
        }
    }
}

impl<S: State> CertificateBuilder<S> {
    pub fn not_before(self, year: i32, month: u8, day: u8) -> CertificateBuilder<SetNotBefore<S>>
    where
        S::NotBefore: IsUnset,
    {
        self.not_before_internal(Date { year, month, day })
    }

    pub fn not_after(self, year: i32, month: u8, day: u8) -> CertificateBuilder<SetNotAfter<S>>
    where
        S::NotAfter: IsUnset,
    {
        self.not_after_internal(Date { year, month, day })
    }

    pub fn subject_alt_names<V, V2>(self, data: V) -> CertificateBuilder<SetSubjectAltNames<S>>
    where
        S::SubjectAltNames: IsUnset,
        V: Into<Vec<V2>>,
        V2: Into<String>,
    {
        let data = data.into().into_iter().map(Into::into).collect::<Vec<_>>();

        self.subject_alt_names_internal(data)
    }

    pub fn distinguished_name<V, V2>(self, data: V) -> CertificateBuilder<SetDistinguishedName<S>>
    where
        S::DistinguishedName: IsUnset,
        V: Into<Vec<(DnType, V2)>>,
        V2: Into<String>,
    {
        let data = data
            .into()
            .into_iter()
            .map(|(t, t2)| (t, t2.into()))
            .collect::<Vec<_>>();

        self.distinguished_name_internal(data)
    }
}

impl<S: IsComplete> CertificateBuilder<S> {
    pub fn generate(self) -> Result<CertifiedKey, CertificateErr> {
        self.build().generate()
    }
}

impl Certificate {
    /// flutter_rust_bridge:sync
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate(self) -> Result<CertifiedKey, CertificateErr> {
        use rcgen::{CertificateParams, DistinguishedName, Issuer, KeyPair};
        use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let signing_key = if self.signature.is_rsa() {
            #[cfg(feature = "extra_signature_algos")]
            let Some(key_size) = self.rsa_key_size else {
                return Err(CertificateErr::RsaKeySizeNotSet);
            };

            if cfg!(feature = "extra_signature_algos") {
                KeyPair::generate_rsa_for(self.signature.into(), key_size.into())?
            } else {
                unreachable!("is_rsa() should not have returned true")
            }
        } else {
            KeyPair::generate_for(self.signature.into())?
        };

        let mut cert = CertificateParams::new(self.subject_alt_names)?;
        cert.is_ca = self.is_ca;
        cert.not_before = self.not_before.into();
        cert.not_after = self.not_after.into();
        cert.serial_number = self.serial_number.map(Into::into);
        cert.distinguished_name = {
            let mut dn = DistinguishedName::new();
            for (ty, val) in self.distinguished_name {
                dn.push(ty.into(), val);
            }
            dn
        };
        cert.key_usages = self.key_usages.into_iter().map(Into::into).collect();
        cert.extended_key_usages = self
            .extended_key_usages
            .into_iter()
            .map(Into::into)
            .collect();
        cert.crl_distribution_points = self
            .crl_distribution_points
            .into_iter()
            .map(Into::into)
            .collect();
        cert.custom_extensions = self.custom_extensions.into_iter().map(Into::into).collect();
        cert.use_authority_key_identifier_extension = self.use_authority_key_identifier_extension;
        cert.key_identifier_method = self.key_identifier_method.into();

        let cert = if let (Some(crt), Some(key)) = (self.ca_cert, self.ca_key) {
            let issuer_key = 'ok: {
                if let Ok(ca) = str::from_utf8(&key) {
                    if let Ok(key) = KeyPair::from_pem(ca) {
                        break 'ok key;
                    }

                    if let Ok(key) = KeyPair::from_pem_and_sign_algo(ca, self.signature.into()) {
                        break 'ok key;
                    }

                    if let Ok(key) =
                        KeyPair::from_pkcs8_pem_and_sign_algo(ca, self.signature.into())
                    {
                        break 'ok key;
                    }
                }

                // try to auto detect der + sig
                if let Ok(key) = KeyPair::try_from(&*key) {
                    break 'ok key;
                }

                if let Ok(key) = TryInto::<PrivateKeyDer>::try_into(&*key)
                    && let Ok(key) = KeyPair::from_der_and_sign_algo(&key, self.signature.into())
                {
                    break 'ok key;
                }

                let key = PrivatePkcs8KeyDer::from(&*key);
                if let Ok(key) = KeyPair::from_pkcs8_der_and_sign_algo(&key, self.signature.into())
                {
                    break 'ok key;
                }

                return Err(CertificateErr::CaCertTypeErr);
            };

            let issuer = if let Ok(pem) = str::from_utf8(&crt) {
                Issuer::from_ca_cert_pem(pem, issuer_key)?
            } else {
                let der = CertificateDer::from_slice(&crt);
                Issuer::from_ca_cert_der(&der, issuer_key)?
            };

            cert.signed_by(&signing_key, &issuer)?
        } else {
            cert.self_signed(&signing_key)?
        };

        Ok(CertifiedKey { cert, signing_key })
    }
}
