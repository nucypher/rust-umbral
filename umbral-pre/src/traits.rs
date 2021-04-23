use core::cmp::Ordering;
use core::ops::Sub;
use generic_array::sequence::Split;
use generic_array::{ArrayLength, GenericArray};
use typenum::{Diff, Unsigned, U1};

/// Errors that can happen during object deserialization.
#[derive(Debug, PartialEq)]
pub enum DeserializationError {
    /// Failed to construct the object from a given bytestring (with the correct length).
    ConstructionFailure,
    /// The given bytestring is too short.
    NotEnoughBytes,
    /// The given bytestring is too long.
    TooManyBytes,
}

/// A trait denoting that the object can be represented as an array of bytes
/// with size known at compile time.
pub trait RepresentableAsArray: Sized {
    /// Resulting array length.
    type Size: ArrayLength<u8>;

    // It would be nice to have a dependent type
    // type Array = GenericArray<u8, Self::Size>;
    // but it's currently an unstable feature or Rust.
}

/// A trait denoting that the object can be serialized to an array of bytes
/// with size known at compile time.
pub trait SerializableToArray: RepresentableAsArray {
    /// Produces a byte array with the object's contents.
    fn to_array(&self) -> GenericArray<u8, Self::Size>;
}

/// A trait denoting that the object can be deserialized from an array of bytes
/// with size known at compile time.
pub trait DeserializableFromArray: RepresentableAsArray {
    /// Attempts to produce the object back from the serialized form.
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError>;

    /// Attempts to produce the object back from a dynamically sized byte array,
    /// checking that its length is correct.
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, DeserializationError> {
        let bytes_slice = bytes.as_ref();
        match bytes_slice.len().cmp(&Self::Size::to_usize()) {
            Ordering::Greater => Err(DeserializationError::TooManyBytes),
            Ordering::Less => Err(DeserializationError::NotEnoughBytes),
            Ordering::Equal => {
                Self::from_array(GenericArray::<u8, Self::Size>::from_slice(bytes_slice))
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
    ) -> Result<(Self, GenericArray<u8, Diff<U, Self::Size>>), DeserializationError>
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
    fn take_last(arr: GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
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
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
        let bytes_slice = arr.as_slice();
        match bytes_slice[0] {
            0u8 => Ok(false),
            1u8 => Ok(true),
            _ => Err(DeserializationError::ConstructionFailure),
        }
    }
}

#[cfg(test)]
mod tests {

    use generic_array::sequence::Concat;
    use generic_array::GenericArray;
    use typenum::{op, U1, U2};

    use super::{
        DeserializableFromArray, DeserializationError, RepresentableAsArray, SerializableToArray,
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
        fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
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
        fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
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
        fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, DeserializationError> {
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
        assert_eq!(s, Err(DeserializationError::ConstructionFailure))
    }

    #[test]
    fn test_invalid_length() {
        // An excessive byte at the end
        let s_arr: [u8; 7] = [0x00, 0x01, 0x02, 0x00, 0x03, 0x01, 0x00];
        let s = SomeStruct::from_bytes(&s_arr);
        assert_eq!(s, Err(DeserializationError::TooManyBytes))
    }
}
