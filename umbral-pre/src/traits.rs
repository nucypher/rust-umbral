#[cfg(feature = "default-serialization")]
use alloc::boxed::Box;

use core::fmt;

use snafu::Snafu;

#[cfg(feature = "default-serialization")]
use serde::{Deserialize, Serialize};

/// The provided bytestring is of an incorrect size.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "Bytestring size mismatch: expected {} bytes, got {}",
    expected_size,
    received_size
))]
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

/// Default serialization of an object that is used in all the bindings.
/// Uses MessagePack format.
#[cfg(feature = "default-serialization")]
pub trait DefaultSerialize: Serialize {
    /// Serializes this object.
    fn to_bytes(&self) -> Result<Box<[u8]>, rmp_serde::encode::Error> {
        rmp_serde::to_vec(self).map(|v| v.into_boxed_slice())
    }
}

/// Default deserialization of an object that is used in all the bindings.
/// Uses MessagePack format.
#[cfg(feature = "default-serialization")]
pub trait DefaultDeserialize<'de>: Deserialize<'de> {
    /// Deserializes a bytestring into this object.
    fn from_bytes(bytes: &'de [u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(bytes)
    }
}
