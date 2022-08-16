use alloc::format;
use alloc::string::String;
use core::cmp::Ordering;
use core::fmt;
use core::ops::Sub;

use generic_array::sequence::Split;
use generic_array::{ArrayLength, GenericArray};
use typenum::{Diff, Unsigned, U1, U8};

use crate::secret_box::SecretBox;

/// Errors that can happen during deserializing an object from a bytestring of correct length.
#[derive(Debug, PartialEq, Eq)]
pub struct ConstructionError {
    /// The name of the type that was being deserialized
    /// (can be one of the nested fields).
    type_name: String,
    /// An associated error message.
    message: String,
}

impl ConstructionError {
    /// Creates a new `ConstructionError`.
    pub fn new(type_name: &str, message: &str) -> Self {
        Self {
            type_name: type_name.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ConstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Failed to construct a {} object: {}",
            self.type_name, self.message
        )
    }
}

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

/// Errors that can happen during object deserialization.
#[derive(Debug, PartialEq, Eq)]
pub enum DeserializationError {
    /// Failed to construct the object from a given bytestring (with the correct length).
    ConstructionFailure(ConstructionError),
    /// The given bytestring is too short or too long.
    SizeMismatch(SizeMismatchError),
}

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConstructionFailure(err) => write!(f, "{}", err),
            Self::SizeMismatch(err) => write!(f, "{}", err),
        }
    }
}

/// A trait denoting that the object can be represented as an array of bytes
/// with size known at compile time.
pub trait RepresentableAsArray: Sized {
    /// Resulting array length.
    type Size: ArrayLength<u8>;

    // It would be nice to have a dependent type
    // type Array = GenericArray<u8, Self::Size>;
    // but it's currently an unstable feature or Rust.

    /// Resulting array length exposed as a runtime method.
    fn serialized_size() -> usize {
        Self::Size::to_usize()
    }
}

/// A trait denoting that the object can be serialized to an array of bytes
/// with size known at compile time.
pub trait SerializableToArray: RepresentableAsArray {
    /// Produces a byte array with the object's contents.
    fn to_array(&self) -> GenericArray<u8, Self::Size>;
}

/// A trait denoting that the object can be serialized to an array of bytes
/// containing secret data.
pub trait SerializableToSecretArray: RepresentableAsArray {
    /// Produces a byte array with the object's contents, wrapped in a secret container.
    fn to_secret_array(&self) -> SecretBox<GenericArray<u8, Self::Size>>;
}

/// A trait denoting that the object can be deserialized from an array of bytes
/// with size known at compile time.
pub trait DeserializableFromArray: RepresentableAsArray {
    /// Attempts to produce the object back from the serialized form.
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError>;

    /// Attempts to produce the object back from a dynamically sized byte array,
    /// checking that its length is correct.
    fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, DeserializationError> {
        let data_slice = data.as_ref();
        let received_size = data_slice.len();
        let expected_size = Self::serialized_size();
        match received_size.cmp(&expected_size) {
            Ordering::Greater | Ordering::Less => Err(DeserializationError::SizeMismatch(
                SizeMismatchError::new(received_size, expected_size),
            )),
            Ordering::Equal => {
                Self::from_array(GenericArray::<u8, Self::Size>::from_slice(data_slice))
                    .map_err(DeserializationError::ConstructionFailure)
            }
        }
    }

    /// Used to implement [`from_array()`](`Self::from_array()`) for structs whose fields
    /// implement [`SerializableToArray`].
    ///
    /// Attempts to split off enough bytes from `arr` to call
    /// [`from_array()`](`Self::from_array()`),
    /// and if it succeeds, returns the resulting object and the rest of the array.
    #[allow(clippy::type_complexity)]
    fn take<U>(
        arr: GenericArray<u8, U>,
    ) -> Result<(Self, GenericArray<u8, Diff<U, Self::Size>>), ConstructionError>
    where
        U: ArrayLength<u8> + Sub<Self::Size>,
        Diff<U, Self::Size>: ArrayLength<u8>,
    {
        let (res_bytes, rest): (GenericArray<u8, Self::Size>, GenericArray<u8, _>) = arr.split();
        let maybe_res = Self::from_array(&res_bytes);
        maybe_res.map(|res| (res, rest))
    }

    /// A variant of [`take()`](`Self::take()`) to be called for the last field of the struct,
    /// where no remainder of the array is expected.
    fn take_last(arr: GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        Self::from_array(&arr)
    }
}

impl RepresentableAsArray for bool {
    type Size = U1;
}

impl SerializableToArray for bool {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        GenericArray::<u8, Self::Size>::from([*self as u8])
    }
}

impl DeserializableFromArray for bool {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        let bytes_slice = arr.as_slice();
        match bytes_slice[0] {
            0u8 => Ok(false),
            1u8 => Ok(true),
            _ => Err(ConstructionError::new(
                "bool",
                &format!("Expected 0x0 or 0x1, got 0x{:x?}", bytes_slice[0]),
            )),
        }
    }
}

/// A reflection trait providing access to the type's name.
pub trait HasTypeName {
    /// Returns a string with the name of the type
    /// (intended for displaying to humans).
    fn type_name() -> &'static str;
    // There is `std::any::type_name()` available, but its format is not guaranteed;
    // for example, it can prepend modules names.
    // We just want the struct name, without any additions.
}

/// A `fmt` implementation for types with secret data.
pub(crate) fn fmt_secret<T: HasTypeName>(f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:...", T::type_name())
}

/// A `fmt` implementation for types with public data.
pub(crate) fn fmt_public<T>(obj: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result
where
    T: HasTypeName + SerializableToArray + RepresentableAsArray,
    <T as RepresentableAsArray>::Size: Sub<U8>,
    Diff<<T as RepresentableAsArray>::Size, U8>: ArrayLength<u8>,
{
    let bytes = (*obj).to_array();
    let (to_show, _): (GenericArray<u8, U8>, GenericArray<u8, _>) = bytes.split();
    let mut hex_repr = [b'*'; 16]; // exactly 16 bytes long, to fit the encode() result
    hex::encode_to_slice(to_show, &mut hex_repr).map_err(|_| fmt::Error)?;
    write!(
        f,
        "{}:{}",
        T::type_name(),
        String::from_utf8_lossy(&hex_repr)
    )
}

#[cfg(test)]
mod tests {

    use generic_array::sequence::Concat;
    use generic_array::GenericArray;
    use typenum::{op, U1, U2};

    use super::{
        ConstructionError, DeserializableFromArray, DeserializationError, RepresentableAsArray,
        SerializableToArray, SizeMismatchError,
    };

    impl RepresentableAsArray for u8 {
        type Size = U1;
    }

    impl SerializableToArray for u8 {
        fn to_array(&self) -> GenericArray<u8, Self::Size> {
            GenericArray::<u8, Self::Size>::from([*self])
        }
    }

    impl DeserializableFromArray for u8 {
        fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
            Ok(arr.as_slice()[0])
        }
    }

    impl RepresentableAsArray for u16 {
        type Size = U2;
    }

    impl SerializableToArray for u16 {
        fn to_array(&self) -> GenericArray<u8, Self::Size> {
            GenericArray::<u8, Self::Size>::from([(self >> 8) as u8, *self as u8])
        }
    }

    impl DeserializableFromArray for u16 {
        fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
            let b1 = arr.as_slice()[0];
            let b2 = arr.as_slice()[1];
            Ok(((b1 as u16) << 8) + (b2 as u16))
        }
    }

    #[derive(Debug, PartialEq)]
    struct SomeStruct {
        f1: u16,
        f2: u8,
        f3: u16,
        f4: bool,
    }

    type U8Size = <u8 as RepresentableAsArray>::Size;
    type U16Size = <u16 as RepresentableAsArray>::Size;
    type BoolSize = <bool as RepresentableAsArray>::Size;

    impl RepresentableAsArray for SomeStruct {
        type Size = op!(U16Size + U8Size + U16Size + BoolSize);
    }

    impl SerializableToArray for SomeStruct {
        fn to_array(&self) -> GenericArray<u8, Self::Size> {
            self.f1
                .to_array()
                .concat(self.f2.to_array())
                .concat(self.f3.to_array())
                .concat(self.f4.to_array())
        }
    }

    impl DeserializableFromArray for SomeStruct {
        fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
            let (f1, rest) = u16::take(*arr)?;
            let (f2, rest) = u8::take(rest)?;
            let (f3, rest) = u16::take(rest)?;
            let f4 = bool::take_last(rest)?;
            Ok(Self { f1, f2, f3, f4 })
        }
    }

    #[test]
    fn test_serialize() {
        let s = SomeStruct {
            f1: 1,
            f2: 2,
            f3: 3,
            f4: true,
        };
        let s_arr = s.to_array();

        let s_arr_ref: [u8; 6] = [0x00, 0x01, 0x02, 0x00, 0x03, 0x01];
        assert_eq!(s_arr.as_slice(), &s_arr_ref);

        let s_from_arr = SomeStruct::from_array(&s_arr).unwrap();
        assert_eq!(s_from_arr, s);

        let s_from_bytes = SomeStruct::from_bytes(&s_arr_ref).unwrap();
        assert_eq!(s_from_bytes, s);
    }

    #[test]
    fn test_invalid_data() {
        // invalid value for `f4` (`bool` must be either 0 or 1)
        let s_arr: [u8; 6] = [0x00, 0x01, 0x02, 0x00, 0x03, 0x02];
        let s = SomeStruct::from_bytes(&s_arr);
        assert_eq!(
            s,
            Err(DeserializationError::ConstructionFailure(
                ConstructionError::new("bool", "Expected 0x0 or 0x1, got 0x2")
            ))
        )
    }

    #[test]
    fn test_invalid_length() {
        // An excessive byte at the end
        let s_arr: [u8; 7] = [0x00, 0x01, 0x02, 0x00, 0x03, 0x01, 0x00];
        let s = SomeStruct::from_bytes(&s_arr);
        assert_eq!(
            s,
            Err(DeserializationError::SizeMismatch(SizeMismatchError::new(
                7, 6
            )))
        )
    }
}
