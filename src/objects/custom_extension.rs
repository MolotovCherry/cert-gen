/// A custom extension of a certificate, as specified in
/// [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.2)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CustomExtension(rcgen::CustomExtension);

impl CustomExtension {
    /// Creates a new acmeIdentifier extension for ACME TLS-ALPN-01
    /// as specified in [RFC 8737](https://tools.ietf.org/html/rfc8737#section-3)
    ///
    /// Returns None if the passed `sha_digest` parameter doesn't hold 32 bytes (256 bits).
    /// flutter_rust_bridge:sync
    pub fn new_acme_identifier(sha_digest: &[u8]) -> Option<Self> {
        if sha_digest.len() != 32 {
            return None;
        }

        let ce = rcgen::CustomExtension::new_acme_identifier(sha_digest);
        Some(Self(ce))
    }

    /// Create a new custom extension with the specified content
    /// flutter_rust_bridge:sync
    pub fn from_oid_content(oid: &[u64], content: Vec<u8>) -> Self {
        let ce = rcgen::CustomExtension::from_oid_content(oid, content);
        Self(ce)
    }

    /// Sets the criticality flag of the extension.
    /// flutter_rust_bridge:sync
    pub fn set_criticality(&mut self, criticality: bool) {
        self.0.set_criticality(criticality);
    }

    /// Obtains the criticality flag of the extension.
    /// flutter_rust_bridge:sync
    pub fn criticality(&self) -> bool {
        self.0.criticality()
    }

    /// Obtains the content of the extension.
    /// flutter_rust_bridge:sync
    pub fn content(&self) -> &[u8] {
        self.0.content()
    }

    /// Obtains the OID components of the extensions, as u64 pieces
    /// flutter_rust_bridge:sync
    pub fn oid_components(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.oid_components()
    }
}

impl From<CustomExtension> for rcgen::CustomExtension {
    fn from(value: CustomExtension) -> Self {
        value.0
    }
}
