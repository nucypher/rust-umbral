use crate::capsule_frag::CapsuleFrag;
use crate::constants::{const_non_interactive, const_x_coordinate};
use crate::curve::{
    curve_generator, point_to_bytes, random_scalar, scalar_to_bytes, CurvePoint, CurvePointSize,
    CurveScalar, CurveScalarSize,
};
use crate::key_frag::KeyFrag;
use crate::keys::{UmbralPrivateKey, UmbralPublicKey};
use crate::params::UmbralParameters;
use crate::random_oracles::hash_to_scalar;

#[cfg(feature = "std")]
use std::vec::Vec;

use core::ops::Add;
use generic_array::sequence::Concat;
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

#[derive(Clone, Copy, Debug)]
pub struct Capsule {
    pub(crate) params: UmbralParameters,
    pub(crate) point_e: CurvePoint,
    pub(crate) point_v: CurvePoint,
    pub(crate) signature: CurveScalar,
}

type CapsuleSize =
    <<CurvePointSize as Add<CurvePointSize>>::Output as Add<CurveScalarSize>>::Output;

impl Capsule {
    pub fn to_bytes(&self) -> GenericArray<u8, CapsuleSize> {
        point_to_bytes(&self.point_e)
            .concat(point_to_bytes(&self.point_v))
            .concat(scalar_to_bytes(&self.signature))
    }

    pub fn with_correctness_keys(
        &self,
        delegating: &UmbralPublicKey,
        receiving: &UmbralPublicKey,
        verifying: &UmbralPublicKey,
    ) -> PreparedCapsule {
        PreparedCapsule {
            capsule: *self,
            delegating_key: *delegating,
            receiving_key: *receiving,
            verifying_key: *verifying,
        }
    }

    pub fn verify(&self) -> bool {
        let g = curve_generator();
        let h = hash_to_scalar(&[self.point_e, self.point_v], None);
        &g * &self.signature == &self.point_v + &(&self.point_e * &h)
    }

    /// Generates a symmetric key and its associated KEM ciphertext
    pub fn from_pubkey(
        params: &UmbralParameters,
        alice_pubkey: &UmbralPublicKey,
    ) -> (Capsule, GenericArray<u8, CurvePointSize>) {
        let g = curve_generator();

        let priv_r = random_scalar();
        let pub_r = &g * &priv_r;

        let priv_u = random_scalar();
        let pub_u = &g * &priv_u;

        let h = hash_to_scalar(&[pub_r, pub_u], None);

        let s = &priv_u + (&priv_r * &h);

        let shared_key = &alice_pubkey.to_point() * &(&priv_r + &priv_u);

        let capsule = Self {
            params: *params,
            point_e: pub_r,
            point_v: pub_u,
            signature: s,
        };

        (capsule, point_to_bytes(&shared_key))
    }

    /// Derive the same symmetric key
    pub fn open_original(
        &self,
        private_key: &UmbralPrivateKey,
    ) -> GenericArray<u8, CurvePointSize> {
        let shared_key = (&self.point_e + &self.point_v) * &private_key.to_scalar();
        point_to_bytes(&shared_key)
    }

    fn open_reencrypted_generic<LC: LambdaCoeff>(
        &self,
        receiving_privkey: &UmbralPrivateKey,
        delegating_key: &UmbralPublicKey,
        cfrags: &[CapsuleFrag],
    ) -> GenericArray<u8, CurvePointSize> {
        let pub_key = receiving_privkey.public_key().to_point();
        let priv_key = receiving_privkey.to_scalar();

        let precursor = cfrags[0].precursor;
        let dh_point = &precursor * &priv_key;

        // Combination of CFrags via Shamir's Secret Sharing reconstruction
        let lc = LC::new(cfrags, &[precursor, pub_key, dh_point]);

        let mut e_prime = CurvePoint::identity();
        let mut v_prime = CurvePoint::identity();
        for (i, cfrag) in (&cfrags).iter().enumerate() {
            assert!(precursor == cfrag.precursor);
            let lambda_i = lc.lambda_coeff(i);
            e_prime += &cfrag.point_e1 * &lambda_i;
            v_prime += &cfrag.point_v1 * &lambda_i;
        }

        // Secret value 'd' allows to make Umbral non-interactive
        let d = hash_to_scalar(
            &[precursor, pub_key, dh_point],
            Some(&const_non_interactive()),
        );

        let e = self.point_e;
        let v = self.point_v;
        let s = self.signature;
        let h = hash_to_scalar(&[e, v], None);

        let orig_pub_key = delegating_key.to_point();

        assert!(&orig_pub_key * &(&s * &d.invert().unwrap()) == &(&e_prime * &h) + &v_prime);
        //    raise GenericUmbralError()

        let shared_key = (&e_prime + &v_prime) * &d;
        point_to_bytes(&shared_key)
    }

    /// Derive the same symmetric encapsulated_key
    #[cfg(feature = "std")]
    pub fn open_reencrypted(
        &self,
        receiving_privkey: &UmbralPrivateKey,
        delegating_key: &UmbralPublicKey,
        cfrags: &[CapsuleFrag],
    ) -> GenericArray<u8, CurvePointSize> {
        self.open_reencrypted_generic::<LambdaCoeffHeap>(receiving_privkey, delegating_key, cfrags)
    }

    /// Derive the same symmetric encapsulated_key
    pub fn open_reencrypted_heapless<Threshold: ArrayLength<CurveScalar> + Unsigned>(
        &self,
        receiving_privkey: &UmbralPrivateKey,
        delegating_key: &UmbralPublicKey,
        cfrags: &[CapsuleFrag],
    ) -> GenericArray<u8, CurvePointSize> {
        self.open_reencrypted_generic::<LambdaCoeffHeapless<Threshold>>(
            receiving_privkey,
            delegating_key,
            cfrags,
        )
    }
}

fn lambda_coeff(xs: &[CurveScalar], i: usize) -> CurveScalar {
    let mut res = CurveScalar::one();
    for j in 0..xs.len() {
        if j != i {
            res = &res * &xs[j] * &(&xs[j] - &xs[i]).invert().unwrap();
        }
    }
    res
}

trait LambdaCoeff {
    fn new(cfrags: &[CapsuleFrag], points: &[CurvePoint]) -> Self;
    fn lambda_coeff(&self, i: usize) -> CurveScalar;
}

struct LambdaCoeffHeapless<Threshold: ArrayLength<CurveScalar> + Unsigned>(
    GenericArray<CurveScalar, Threshold>,
);

impl<Threshold: ArrayLength<CurveScalar> + Unsigned> LambdaCoeff
    for LambdaCoeffHeapless<Threshold>
{
    fn new(cfrags: &[CapsuleFrag], points: &[CurvePoint]) -> Self {
        let mut result = GenericArray::<CurveScalar, Threshold>::default();
        for i in 0..<Threshold as Unsigned>::to_usize() {
            let customization_string =
                const_x_coordinate().concat(scalar_to_bytes(&cfrags[i].kfrag_id));
            result[i] = hash_to_scalar(points, Some(&customization_string));
        }
        Self(result)
    }

    fn lambda_coeff(&self, i: usize) -> CurveScalar {
        lambda_coeff(&self.0, i)
    }
}

#[cfg(feature = "std")]
struct LambdaCoeffHeap(Vec<CurveScalar>);

#[cfg(feature = "std")]
impl LambdaCoeff for LambdaCoeffHeap {
    fn new(cfrags: &[CapsuleFrag], points: &[CurvePoint]) -> Self {
        let mut result = Vec::<CurveScalar>::with_capacity(cfrags.len());
        for cfrag in cfrags {
            let customization_string =
                const_x_coordinate().concat(scalar_to_bytes(&cfrag.kfrag_id));
            result.push(hash_to_scalar(points, Some(&customization_string)));
        }
        Self(result)
    }

    fn lambda_coeff(&self, i: usize) -> CurveScalar {
        lambda_coeff(&self.0, i)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PreparedCapsule {
    pub(crate) capsule: Capsule,
    pub(crate) delegating_key: UmbralPublicKey,
    pub(crate) receiving_key: UmbralPublicKey,
    pub(crate) verifying_key: UmbralPublicKey,
}

impl PreparedCapsule {
    pub fn verify_cfrag(&self, cfrag: &CapsuleFrag) -> bool {
        cfrag.verify(
            &self.capsule,
            &self.delegating_key,
            &self.receiving_key,
            &self.verifying_key,
        )
    }

    pub fn verify_kfrag(&self, kfrag: &KeyFrag) -> bool {
        kfrag.verify(
            &self.verifying_key,
            Some(&self.delegating_key),
            Some(&self.receiving_key),
        )
    }

    pub fn reencrypt(
        &self,
        kfrag: &KeyFrag,
        metadata: Option<&[u8]>,
        verify_kfrag: bool,
    ) -> Option<CapsuleFrag> {
        if verify_kfrag && !self.verify_kfrag(&kfrag) {
            return None;
        }

        Some(CapsuleFrag::from_kfrag(&self.capsule, &kfrag, metadata))
    }

    #[cfg(feature = "std")]
    pub fn open_reencrypted(
        &self,
        cfrags: &[CapsuleFrag],
        receiving_privkey: &UmbralPrivateKey,
        check_proof: bool,
    ) -> GenericArray<u8, CurvePointSize> {
        if check_proof {
            // TODO: return Result with Error set to offending cfrag indices or something
            for cfrag in cfrags {
                assert!(self.verify_cfrag(cfrag));
            }
        }

        self.capsule
            .open_reencrypted(receiving_privkey, &self.delegating_key, cfrags)
    }

    /*
    Activates the Capsule from the attached CFrags,
    opens the Capsule and returns what is inside.

    This will often be a symmetric key.
    */
    pub fn open_reencrypted_heapless<Threshold: ArrayLength<CurveScalar> + Unsigned>(
        &self,
        cfrags: &[CapsuleFrag],
        receiving_privkey: &UmbralPrivateKey,
        check_proof: bool,
    ) -> GenericArray<u8, CurvePointSize> {
        if check_proof {
            // TODO: return Result with Error set to offending cfrag indices or something
            for cfrag in cfrags {
                assert!(self.verify_cfrag(cfrag));
            }
        }

        self.capsule.open_reencrypted_heapless::<Threshold>(
            receiving_privkey,
            &self.delegating_key,
            cfrags,
        )
    }
}
