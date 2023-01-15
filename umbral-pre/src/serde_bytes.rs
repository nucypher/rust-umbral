//! Utility functions for efficient bytestring serialization with `serde`
//! (by default they are serialized as vectors of integers).

use alloc::boxed::Box;
use alloc::format;
use core::any::type_name;
use core::fmt;
use core::marker::PhantomData;

use serde::{de, Deserializer, Serializer};

pub(crate) enum Encoding {
    /// Use base64 representation for byte arrays.
    Base64,
    /// Use hex representation for byte arrays.
    Hex,
}

struct B64Visitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for B64Visitor<T>
where
    T: TryFromBytes,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b64-encoded {} bytes", type_name::<T>())
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = base64::decode(v).map_err(de::Error::custom)?;
        T::try_from_bytes(&bytes).map_err(de::Error::custom)
    }
}

struct HexVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for HexVisitor<T>
where
    T: TryFromBytes,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x-prefixed hex-encoded bytes of {}", type_name::<T>())
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() < 2 {
            return Err(de::Error::invalid_length(
                v.len(),
                &"0x-prefixed hex-encoded bytes",
            ));
        }
        if &v[..2] != "0x" {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(v),
                &"0x-prefixed hex-encoded bytes",
            ));
        }
        let bytes = hex::decode(&v[2..]).map_err(de::Error::custom)?;
        T::try_from_bytes(&bytes).map_err(de::Error::custom)
    }
}

struct BytesVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for BytesVisitor<T>
where
    T: TryFromBytes,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", type_name::<T>())
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        T::try_from_bytes(v).map_err(de::Error::custom)
    }
}

/// A helper function that will serialize a byte array efficiently
/// depending on whether the target format is text or binary based.
pub(crate) fn serialize_with_encoding<T, S>(
    obj: &T,
    serializer: S,
    encoding: Encoding,
) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    if serializer.is_human_readable() {
        let encoded = match encoding {
            Encoding::Base64 => base64::encode(obj.as_ref()),
            Encoding::Hex => format!("0x{}", hex::encode(obj.as_ref())),
        };
        serializer.serialize_str(&encoded)
    } else {
        serializer.serialize_bytes(obj.as_ref())
    }
}

/// A helper function that will deserialize from a byte array,
/// matching the format used by [`serde_serialize`].
pub(crate) fn deserialize_with_encoding<'de, T, D>(
    deserializer: D,
    encoding: Encoding,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TryFromBytes,
{
    if deserializer.is_human_readable() {
        match encoding {
            Encoding::Base64 => deserializer.deserialize_str(B64Visitor::<T>(PhantomData)),
            Encoding::Hex => deserializer.deserialize_str(HexVisitor::<T>(PhantomData)),
        }
    } else {
        deserializer.deserialize_bytes(BytesVisitor::<T>(PhantomData))
    }
}

pub mod as_hex {
    //! A module containing serialization and deserialization function
    //! that use hex (`0x`-prefixed) representation for bytestrings in human-readable formats.
    //!
    //! To be used in `[serde(with)]` field attribute.

    use super::*;

    /// Serialize an object representable as bytes using `0x`-prefixed hex encoding
    /// if the target format is human-readable, and plain bytes otherwise.
    pub fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serialize_with_encoding(obj, serializer, Encoding::Hex)
    }

    /// Deserialize an object representable as bytes assuming `0x`-prefixed hex encoding
    /// if the source format is human-readable, and plain bytes otherwise.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFromBytes,
    {
        deserialize_with_encoding(deserializer, Encoding::Hex)
    }
}

pub mod as_base64 {
    //! A module containing serialization and deserialization function
    //! that use hex (`0x`-prefixed) representation for bytestrings.
    //!
    //! To be used in `[serde(with)]` field attribute.

    use super::*;

    /// Serialize an object representable as bytes using `base64` encoding
    /// if the target format is human-readable, and plain bytes otherwise.
    pub fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serialize_with_encoding(obj, serializer, Encoding::Base64)
    }

    /// Deserialize an object representable as bytes assuming `base64` encoding
    /// if the source format is human-readable, and plain bytes otherwise.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFromBytes,
    {
        deserialize_with_encoding(deserializer, Encoding::Base64)
    }
}

/*
Ideally, we would generalize `deserialize()` for anything supporting `TryFrom<&[u8]>`.
But we want the associated `Error` to be `Display`, and for some reason `serde`
does not realize that `<<[u8; N]> as TryFrom<&'a [u8]>>::Error`
(which is equal to `TryFromSliceError`) is `Display`.
So we have to introduce our own trait with an `Error` that is definitely `Display`,
and generalize on that.
See https://github.com/serde-rs/serde/issues/2241
*/

/// A trait providing a way to construct an object from a byte slice.
pub trait TryFromBytes: Sized {
    /// The error returned on construction failure.
    type Error: fmt::Display;

    /// Attempts to construct an object from a byte slice.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
}

impl<const N: usize> TryFromBytes for [u8; N] {
    type Error = core::array::TryFromSliceError;

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(bytes)
    }
}

impl TryFromBytes for Box<[u8]> {
    type Error = core::convert::Infallible;

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(bytes.into())
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use core::fmt;

    use serde::de::DeserializeOwned;
    use serde::Serialize;

    pub(crate) fn check_serialization_roundtrip<T>(obj: &T)
    where
        T: fmt::Debug + PartialEq + Serialize + DeserializeOwned,
    {
        // Check serialization to JSON (human-readable)

        let serialized = serde_json::to_string(obj).unwrap();
        let deserialized: T = serde_json::from_str(&serialized).unwrap();
        assert_eq!(obj, &deserialized);

        // Check serialization to ASN.1 DER (binary)

        let serialized = picky_asn1_der::to_vec(obj).unwrap();
        let deserialized: T = picky_asn1_der::from_bytes(&serialized).unwrap();
        assert_eq!(obj, &deserialized);
    }
}
