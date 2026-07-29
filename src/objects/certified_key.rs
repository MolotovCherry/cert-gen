// Certificate is renamed so as to not confuse the frb generator.
use rcgen::{Certificate as RcCertificate, KeyPair};

pub struct CertifiedKey {
    /// flutter_rust_bridge:ignore
    pub signing_key: KeyPair,
    /// flutter_rust_bridge:ignore
    pub cert: RcCertificate,
}

impl CertifiedKey {
    /// flutter_rust_bridge:sync
    pub fn signing_key_pem(&self) -> String {
        self.signing_key.serialize_pem()
    }

    /// flutter_rust_bridge:sync
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }
}
