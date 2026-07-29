/// The attribute type of a distinguished name entry
/// flutter_rust_bridge:non_opaque
#[allow(clippy::enum_variant_names)]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DnType {
    /// X520countryName
    CountryName,
    /// X520LocalityName
    LocalityName,
    /// X520StateOrProvinceName
    StateOrProvinceName,
    /// X520OrganizationName
    OrganizationName,
    /// X520OrganizationalUnitName
    OrganizationalUnitName,
    /// X520CommonName
    CommonName,
    /// Custom distinguished name type
    CustomDnType(Vec<u64>),
}

impl From<DnType> for rcgen::DnType {
    fn from(value: DnType) -> Self {
        match value {
            DnType::CountryName => Self::CountryName,
            DnType::LocalityName => Self::LocalityName,
            DnType::StateOrProvinceName => Self::StateOrProvinceName,
            DnType::OrganizationName => Self::OrganizationName,
            DnType::OrganizationalUnitName => Self::OrganizationalUnitName,
            DnType::CommonName => Self::CommonName,
            DnType::CustomDnType(items) => Self::CustomDnType(items),
        }
    }
}
