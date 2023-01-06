use core::fmt;

/// The provided bytestring is of an incorrect size.
#[derive(Debug, PartialEq, Eq)]
pub struct SizeMismatchError {
    pub(crate) received_size: usize,
    pub(crate) expected_size: usize,
}

impl SizeMismatchError {
    /// Creates a new `SizeMismatchError`.
    pub fn new(received_size: usize, expected_size: usize) -> Self {
        Self {
            received_size,
            expected_size,
        }
    }
}

impl fmt::Display for SizeMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Bytestring size mismatch: expected {} bytes, got {}",
            self.expected_size, self.received_size
        )
    }
}

/// A `fmt` implementation for types with secret data.
pub(crate) fn fmt_secret(type_name: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:...", type_name)
}

/// A `fmt` implementation for types with public data.
pub(crate) fn fmt_public(
    type_name: &str,
    data_to_show: &impl AsRef<[u8]>,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    let bytes = data_to_show.as_ref();
    let bytes = if bytes.len() > 8 { &bytes[..8] } else { bytes };
    write!(f, "{}:{}", type_name, hex::encode(bytes),)
}
