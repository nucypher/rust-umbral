//! Utilities to interact with `serde`.

use core::fmt;
use core::marker::PhantomData;

use serde::{de, Deserializer, Serializer};

use crate::traits::{DeserializableFromArray, HasTypeName, SerializableToArray};

/// Defines the representation to use in text-based `serde` formats.
pub(crate) enum Representation {
    /// Use base64 representation for byte arrays.
    Base64,
    /// Use hex representation for byte arrays.
    Hex,
}

// We cannot have a generic implementation of Serialize over everything
// that supports SerializableToArray, so we have to use this helper function
// and define implementations manually.
/// A helper function that will serialize a byte array efficiently
/// depending on whether the target format is text or binary based.
pub(crate) fn serde_serialize<T, S>(
    obj: &T,
    serializer: S,
    representation: Representation,
) -> Result<S::Ok, S::Error>
where
    T: SerializableToArray,
    S: Serializer,
{
    if serializer.is_human_readable() {
        let repr = match representation {
            Representation::Base64 => base64::encode(obj.to_array().as_ref()),
            Representation::Hex => hex::encode(obj.to_array().as_ref()),
        };
        serializer.serialize_str(&repr)
    } else {
        serializer.serialize_bytes(obj.to_array().as_ref())
    }
}

struct B64Visitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for B64Visitor<T>
where
    T: DeserializableFromArray + HasTypeName,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b64-encoded {} bytes", T::type_name())
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = base64::decode(v).map_err(de::Error::custom)?;
        T::from_bytes(&bytes).map_err(de::Error::custom)
    }
}

struct HexVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for HexVisitor<T>
where
    T: DeserializableFromArray + HasTypeName,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hex-encoded {} bytes", T::type_name())
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = hex::decode(v).map_err(de::Error::custom)?;
        T::from_bytes(&bytes).map_err(de::Error::custom)
    }
}

struct BytesVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for BytesVisitor<T>
where
    T: DeserializableFromArray + HasTypeName,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", T::type_name())
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        T::from_bytes(v).map_err(de::Error::custom)
    }
}

// We cannot have a generic implementation of Deerialize over everything
// that supports DeserializableFromArray, so we have to use this helper function
// and define implementations manually.
/// A helper function that will deserialize from a byte array,
/// matching the format used by [`serde_serialize`].
pub(crate) fn serde_deserialize<'de, T, D>(
    deserializer: D,
    representation: Representation,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializableFromArray + HasTypeName,
{
    if deserializer.is_human_readable() {
        match representation {
            Representation::Base64 => deserializer.deserialize_str(B64Visitor::<T>(PhantomData)),
            Representation::Hex => deserializer.deserialize_str(HexVisitor::<T>(PhantomData)),
        }
    } else {
        deserializer.deserialize_bytes(BytesVisitor::<T>(PhantomData))
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use core::fmt;

    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use serde_json;

    use super::Representation;
    use crate::SerializableToArray;

    /// A helper function that checks that serialization to a human-readable format
    /// uses b64 encoding, and serialization to a binary format contains plain bytes of the object.
    pub(crate) fn check_serialization<T>(obj: &T, representation: Representation)
    where
        T: SerializableToArray + fmt::Debug + PartialEq + Serialize,
    {
        // Check serialization to JSON (human-readable)

        let serialized = serde_json::to_string(obj).unwrap();

        let substr = match representation {
            Representation::Base64 => base64::encode(obj.to_array().as_ref()),
            Representation::Hex => hex::encode(obj.to_array().as_ref()),
        };

        // check that the serialization contains the properly encoded bytestring
        assert!(serialized.contains(&substr));

        // Check serialization to MessagePack (binary)

        let serialized = rmp_serde::to_vec(obj).unwrap();
        let bytes = obj.to_array();
        // check that the serialization contains the bytestring
        assert!(serialized
            .windows(bytes.len())
            .any(move |sub_slice| sub_slice == bytes.as_ref()));
    }

    pub(crate) fn check_deserialization<T>(obj: &T)
    where
        T: SerializableToArray + fmt::Debug + PartialEq + Serialize + DeserializeOwned,
    {
        // Check serialization to JSON (human-readable)

        let serialized = serde_json::to_string(obj).unwrap();
        let deserialized: T = serde_json::from_str(&serialized).unwrap();
        assert_eq!(obj, &deserialized);

        // Check serialization to MessagePack (binary)

        let serialized = rmp_serde::to_vec(obj).unwrap();
        let deserialized: T = rmp_serde::from_read(&*serialized).unwrap();
        assert_eq!(obj, &deserialized);
    }
}
