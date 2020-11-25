use crate::capsule_frag::CapsuleFrag;
use crate::constants::{NON_INTERACTIVE, X_COORDINATE};
use crate::curve::{CurvePoint, CurveScalar, UmbralPublicKey, UmbralSecretKey};
use crate::hashing::ScalarDigest;
use crate::key_frag::KeyFrag;
use crate::params::UmbralParameters;
use crate::traits::SerializableToArray;

#[cfg(feature = "std")]
use std::vec::Vec;

use generic_array::sequence::{Concat, Split};
use generic_array::{ArrayLength, GenericArray};
use typenum::{op, Unsigned};

#[derive(Clone, Copy, Debug)]
pub struct Capsule {
    pub(crate) params: UmbralParameters,
    pub(crate) point_e: CurvePoint,
    pub(crate) point_v: CurvePoint,
    pub(crate) signature: CurveScalar,
}

type UmbralParametersSize = <UmbralParameters as SerializableToArray>::Size;
type PointSize = <CurvePoint as SerializableToArray>::Size;
type ScalarSize = <CurveScalar as SerializableToArray>::Size;
type PublicKeySize = <UmbralPublicKey as SerializableToArray>::Size;
type CapsuleSize = op!(UmbralParametersSize + PointSize + PointSize + ScalarSize);

impl SerializableToArray for Capsule {
    type Size = CapsuleSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.params
            .to_array()
            .concat(self.point_e.to_array())
            .concat(self.point_v.to_array())
            .concat(self.signature.to_array())
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        // TODO: can fail here; return None in this case
        let sized_bytes = GenericArray::<u8, CapsuleSize>::from_slice(bytes.as_ref());

        let (params_bytes, rest): (
            &GenericArray<u8, UmbralParametersSize>,
            &GenericArray<u8, _>,
        ) = sized_bytes.split();
        let (e_bytes, rest): (&GenericArray<u8, PointSize>, &GenericArray<u8, _>) = rest.split();
        let (v_bytes, signature): (&GenericArray<u8, PointSize>, &GenericArray<u8, _>) =
            rest.split();

        // TODO: propagate error properly
        let params = UmbralParameters::from_bytes(&params_bytes).unwrap();
        let e = CurvePoint::from_bytes(&e_bytes).unwrap();
        let v = CurvePoint::from_bytes(&v_bytes).unwrap();
        let signature = CurveScalar::from_bytes(&signature).unwrap();

        Some(Capsule::new(&params, &e, &v, &signature))
    }
}

impl Capsule {
    fn new(
        params: &UmbralParameters,
        e: &CurvePoint,
        v: &CurvePoint,
        signature: &CurveScalar,
    ) -> Self {
        Self {
            params: *params,
            point_e: *e,
            point_v: *v,
            signature: *signature,
        }
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
        let g = CurvePoint::generator();
        let h = ScalarDigest::new()
            .chain_point(&self.point_e)
            .chain_point(&self.point_v)
            .finalize();
        &g * &self.signature == &self.point_v + &(&self.point_e * &h)
    }

    /// Generates a symmetric key and its associated KEM ciphertext
    pub fn from_pubkey(
        params: &UmbralParameters,
        alice_pubkey: &UmbralPublicKey,
    ) -> (
        Capsule,
        GenericArray<u8, <CurvePoint as SerializableToArray>::Size>,
    ) {
        let g = CurvePoint::generator();

        let priv_r = CurveScalar::random_nonzero();
        let pub_r = &g * &priv_r;

        let priv_u = CurveScalar::random_nonzero();
        let pub_u = &g * &priv_u;

        let h = ScalarDigest::new().chain_points(&[pub_r, pub_u]).finalize();

        let s = &priv_u + &(&priv_r * &h);

        let shared_key = &alice_pubkey.to_point() * &(&priv_r + &priv_u);

        let capsule = Self {
            params: *params,
            point_e: pub_r,
            point_v: pub_u,
            signature: s,
        };

        (capsule, shared_key.to_array())
    }

    /// Derive the same symmetric key
    pub fn open_original(&self, private_key: &UmbralSecretKey) -> GenericArray<u8, PointSize> {
        let shared_key = &(&self.point_e + &self.point_v) * &private_key.to_secret_scalar();
        shared_key.to_array()
    }

    #[allow(clippy::many_single_char_names)]
    fn open_reencrypted_generic<LC: LambdaCoeff>(
        &self,
        receiving_privkey: &UmbralSecretKey,
        delegating_key: &UmbralPublicKey,
        cfrags: &[CapsuleFrag],
    ) -> GenericArray<u8, PointSize> {
        let pub_key = UmbralPublicKey::from_secret_key(receiving_privkey).to_point();

        let precursor = cfrags[0].precursor;
        let dh_point = &precursor * &receiving_privkey.to_secret_scalar();

        // Combination of CFrags via Shamir's Secret Sharing reconstruction
        let lc = LC::new(cfrags, &[precursor, pub_key, dh_point]);

        let mut e_prime = CurvePoint::identity();
        let mut v_prime = CurvePoint::identity();
        for (i, cfrag) in (&cfrags).iter().enumerate() {
            assert!(precursor == cfrag.precursor);
            let lambda_i = lc.lambda_coeff(i);
            e_prime = &e_prime + &(&cfrag.point_e1 * &lambda_i);
            v_prime = &v_prime + &(&cfrag.point_v1 * &lambda_i);
        }

        // Secret value 'd' allows to make Umbral non-interactive
        let d = ScalarDigest::new()
            .chain_points(&[precursor, pub_key, dh_point])
            .chain_bytes(NON_INTERACTIVE)
            .finalize();

        let e = self.point_e;
        let v = self.point_v;
        let s = self.signature;
        let h = ScalarDigest::new().chain_points(&[e, v]).finalize();

        let orig_pub_key = delegating_key.to_point();

        assert!(&orig_pub_key * &(&s * &d.invert().unwrap()) == &(&e_prime * &h) + &v_prime);
        //    raise GenericUmbralError()

        let shared_key = &(&e_prime + &v_prime) * &d;
        shared_key.to_array()
    }

    /// Derive the same symmetric encapsulated_key
    #[cfg(feature = "std")]
    pub fn open_reencrypted(
        &self,
        receiving_privkey: &UmbralSecretKey,
        delegating_key: &UmbralPublicKey,
        cfrags: &[CapsuleFrag],
    ) -> GenericArray<u8, PointSize> {
        self.open_reencrypted_generic::<LambdaCoeffHeap>(receiving_privkey, delegating_key, cfrags)
    }

    /// Derive the same symmetric encapsulated_key
    pub fn open_reencrypted_heapless<Threshold: ArrayLength<CurveScalar> + Unsigned>(
        &self,
        receiving_privkey: &UmbralSecretKey,
        delegating_key: &UmbralPublicKey,
        cfrags: &[CapsuleFrag],
    ) -> GenericArray<u8, PointSize> {
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
            res = &(&res * &xs[j]) * &(&xs[j] - &xs[i]).invert().unwrap();
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
            result[i] = ScalarDigest::new()
                .chain_points(points)
                .chain_bytes(X_COORDINATE)
                .chain_scalar(&cfrags[i].kfrag_id)
                .finalize();
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
            let coeff = ScalarDigest::new()
                .chain_points(points)
                .chain_bytes(X_COORDINATE)
                .chain_scalar(&cfrag.kfrag_id)
                .finalize();
            result.push(coeff);
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

type PreparedCapsuleSize = op!(CapsuleSize + PublicKeySize + PublicKeySize + PublicKeySize);

impl SerializableToArray for PreparedCapsule {
    type Size = PreparedCapsuleSize;

    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.capsule
            .to_array()
            .concat(self.delegating_key.to_array())
            .concat(self.receiving_key.to_array())
            .concat(self.verifying_key.to_array())
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        // TODO: can fail here; return None in this case
        let sized_bytes = GenericArray::<u8, PreparedCapsuleSize>::from_slice(bytes.as_ref());

        let (capsule_bytes, rest): (&GenericArray<u8, CapsuleSize>, &GenericArray<u8, _>) =
            sized_bytes.split();
        let (delegating_key_bytes, rest): (&GenericArray<u8, PublicKeySize>, &GenericArray<u8, _>) =
            rest.split();
        let (receiving_key_bytes, verifying_key_bytes): (
            &GenericArray<u8, PublicKeySize>,
            &GenericArray<u8, _>,
        ) = rest.split();

        // TODO: propagate error properly
        let capsule = Capsule::from_bytes(&capsule_bytes).unwrap();
        let delegating_key = UmbralPublicKey::from_bytes(&delegating_key_bytes).unwrap();
        let receiving_key = UmbralPublicKey::from_bytes(&receiving_key_bytes).unwrap();
        let verifying_key = UmbralPublicKey::from_bytes(&verifying_key_bytes).unwrap();

        Some(PreparedCapsule {
            capsule,
            delegating_key,
            receiving_key,
            verifying_key,
        })
    }
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
        receiving_privkey: &UmbralSecretKey,
        check_proof: bool,
    ) -> GenericArray<u8, PointSize> {
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
        receiving_privkey: &UmbralSecretKey,
        check_proof: bool,
    ) -> GenericArray<u8, PointSize> {
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
