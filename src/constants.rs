// TODO: in the original these were constants from ConstantSorrow.

use generic_array::{GenericArray, arr};
use generic_array::typenum::{U12, U15};

pub fn const_non_interactive() -> GenericArray<u8, U15> {
    GenericArray::<u8, U15>::clone_from_slice(b"NON_INTERACTIVE")
}

pub fn const_x_coordinate() -> GenericArray<u8, U12> {
    GenericArray::<u8, U12>::clone_from_slice(b"X_COORDINATE")
}
