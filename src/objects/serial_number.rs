use std::fmt;

/// A certificate serial number.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SerialNumber {
    inner: Vec<u8>,
}

#[allow(clippy::len_without_is_empty)]
impl SerialNumber {
    /// Create a serial number from the given byte slice.
    /// flutter_rust_bridge:ignore
    pub fn from_slice(bytes: &[u8]) -> SerialNumber {
        let inner = bytes.to_vec();
        SerialNumber { inner }
    }

    /// flutter_rust_bridge:sync
    pub fn from_owned(bytes: Vec<u8>) -> SerialNumber {
        Self::from(bytes)
    }

    /// flutter_rust_bridge:sync
    pub fn from_u64(num: u64) -> SerialNumber {
        Self::from(num)
    }

    /// Return the byte representation of the serial number.
    /// flutter_rust_bridge:sync
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.clone()
    }

    /// Return the length of the serial number in bytes.
    /// flutter_rust_bridge:sync
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let hex: Vec<_> = self.inner.iter().map(|b| format!("{b:02x}")).collect();
        write!(f, "{}", hex.join(":"))
    }
}

impl From<SerialNumber> for rcgen::SerialNumber {
    fn from(value: SerialNumber) -> Self {
        Self::from(value.inner)
    }
}

impl From<Vec<u8>> for SerialNumber {
    fn from(inner: Vec<u8>) -> SerialNumber {
        SerialNumber { inner }
    }
}

impl From<u64> for SerialNumber {
    fn from(u: u64) -> SerialNumber {
        let inner = u.to_be_bytes().into();
        SerialNumber { inner }
    }
}

impl AsRef<[u8]> for SerialNumber {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}
