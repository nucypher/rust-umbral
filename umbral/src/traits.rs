use generic_array::{ArrayLength, GenericArray};
use typenum::U1;

pub trait SerializableToArray
where
    Self: Sized,
{
    type Size: ArrayLength<u8>;

    // TODO: would be nice to have a dependent type
    // type Array = GenericArray<u8, Self::Size>;
    // but it's currently an unstable feature.

    fn to_array(&self) -> GenericArray<u8, Self::Size>;

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self>;
}

impl SerializableToArray for bool {
    type Size = U1;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        *GenericArray::<u8, Self::Size>::from_slice(&[*self as u8])
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        let bytes_slice = bytes.as_ref();
        if bytes_slice.len() != 1 {
            return None;
        }
        match bytes_slice[0] {
            0u8 => Some(false),
            1u8 => Some(true),
            _ => None,
        }
    }
}
