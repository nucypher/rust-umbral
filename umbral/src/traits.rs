use generic_array::{ArrayLength, GenericArray};

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
