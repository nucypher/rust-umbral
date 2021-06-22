/*
This module implements a similar API to what the crate `secrecy` provides.
So, why our own implementation?

First `secrecy::Secret<T>` does not put its contents in a `Box`.
Using `Box` is a general recommendation of working with secret data,
because it prevents the compiler from putting it on stack, thus avoiding possible copies on borrow.

Now, one could use `secrecy::Secret<Box<T>>`.
The problem here is that `secrecy::Secret` requires its type parameter to implement `Zeroize`.
This means that for a foreign type `F` (even if it does implement `Zeroize`)
we need to define `impl Zeroize for Box<F>`.
But the compiler does not allow impls of foreign traits on foreign types.
This means that we also need to wrap `F` in a local type, impl `Zeroize` for the wrapper,
and then for the box of the wrapper.
This is too much boilerplate.

Additionally, `secrecy::Secret<Box<T>>` means that after each `expose_secret()`
we will need to deal with opening the `Box` as well.
It's an inconvenience, albeit a minor one.

The situation may improve in the future, and `secrecy` will actually become usable.
See https://github.com/iqlusioninc/crates/issues/757
*/

use alloc::boxed::Box;

use generic_array::{ArrayLength, GenericArray};
use zeroize::Zeroize;

/// This is a helper trait for [`SecretBox`], asserting that the type implementing it
/// can either be zeroized (in which case [`ensure_zeroized_on_drop`] is implemented accordingly),
/// or is zeroized on drop (in which case [`ensure_zeroized_on_drop`] does nothing).
/// In other words, with this trait we are sure that one way or the other,
/// on drop of [`SecretBox`] the contents are zeroized.
///
/// Ideally these should be two traits, but without trait specialization feature
/// we cannot have two `Drop` implementations depending on which trait the type has.
///
/// Additionally, it allows us to implement [`zeroize::Zeroize`]-like behavior
/// for foreign types for which the original `Zeroize`
/// isn't implemented (for example, [`generic_array::GenericArray`]).
pub trait CanBeZeroizedOnDrop {
    /// This method will be called on drop.
    /// The implementor should zeroize the secret parts of the value if it does not do it itself,
    /// or do nothing otherwise.
    fn ensure_zeroized_on_drop(&mut self);
}

impl<T, N> CanBeZeroizedOnDrop for GenericArray<T, N>
where
    N: ArrayLength<T>,
    T: Zeroize,
{
    fn ensure_zeroized_on_drop(&mut self) {
        self.as_mut_slice().iter_mut().zeroize()
    }
}

/// A container for secret data.
/// Makes the usage of secret data explicit and easy to track,
/// prevents the secret data from being put on stack,
/// and zeroizes the contents on drop.
#[derive(Clone)]
pub struct SecretBox<T>(Box<T>)
where
    T: CanBeZeroizedOnDrop + Clone;

impl<T> SecretBox<T>
where
    T: CanBeZeroizedOnDrop + Clone,
{
    pub(crate) fn new(val: T) -> Self {
        Self(Box::new(val))
    }

    pub fn as_secret(&self) -> &T {
        self.0.as_ref()
    }
}

impl<T> Drop for SecretBox<T>
where
    T: CanBeZeroizedOnDrop + Clone,
{
    fn drop(&mut self) {
        self.0.ensure_zeroized_on_drop()
    }
}
