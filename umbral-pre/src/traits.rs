use core::ops::Sub;
use generic_array::sequence::Split;
use generic_array::{ArrayLength, GenericArray};
use typenum::{Diff, Unsigned, U1};

pub trait SerializableToArray
where
    Self: Sized,
{
    type Size: ArrayLength<u8>;

    // TODO: would be nice to have a dependent type
    // type Array = GenericArray<u8, Self::Size>;
    // but it's currently an unstable feature.

    // TODO: `to_array()` and `from_array()` can be derived automatically for compound structs.

    fn to_array(&self) -> GenericArray<u8, Self::Size>;

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self>;

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        let bytes_slice = bytes.as_ref();
        if bytes_slice.len() != Self::Size::to_usize() {
            return None;
        }
        Self::from_array(GenericArray::<u8, Self::Size>::from_slice(bytes_slice))
    }

    #[allow(clippy::type_complexity)]
    fn take<U>(arr: GenericArray<u8, U>) -> Option<(Self, GenericArray<u8, Diff<U, Self::Size>>)>
    where
        U: ArrayLength<u8> + Sub<Self::Size>,
        Diff<U, Self::Size>: ArrayLength<u8>,
    {
        let (res_bytes, rest): (GenericArray<u8, Self::Size>, GenericArray<u8, _>) = arr.split();
        let maybe_res = Self::from_array(&res_bytes);
        maybe_res.map(|res| (res, rest))
    }

    fn take_last(arr: GenericArray<u8, Self::Size>) -> Option<Self> {
        Self::from_array(&arr)
    }
}

impl SerializableToArray for bool {
    type Size = U1;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        GenericArray::<u8, Self::Size>::from([*self as u8])
    }

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let bytes_slice = arr.as_slice();
        match bytes_slice[0] {
            0u8 => Some(false),
            1u8 => Some(true),
            _ => None,
        }
    }
}
