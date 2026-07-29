/// A certificate revocation list (CRL) distribution point, to be included in a certificate's
/// [distribution points extension](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13) or
/// a CRL's [issuing distribution point extension](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5)
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CrlDistributionPoint {
    /// One or more URI distribution point names, indicating a place the current CRL can
    /// be retrieved. When present, SHOULD include at least one LDAP or HTTP URI.
    /// flutter_rust_bridge:non_final
    pub uris: Vec<String>,
}

impl From<CrlDistributionPoint> for rcgen::CrlDistributionPoint {
    fn from(value: CrlDistributionPoint) -> Self {
        rcgen::CrlDistributionPoint { uris: value.uris }
    }
}
