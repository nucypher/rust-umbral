use crate::capsule_frag::CapsuleFrag;
use crate::constants::{NON_INTERACTIVE, X_COORDINATE};
use crate::curve::{CurvePoint, CurveScalar, UmbralPublicKey, UmbralSecretKey};
use crate::hashing::ScalarDigest;
use crate::params::UmbralParameters;
use crate::traits::SerializableToArray;

use alloc::vec::Vec;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use typenum::op;

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

    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Option<Self> {
        let (params, rest) = UmbralParameters::take(*arr)?;
        let (point_e, rest) = CurvePoint::take(rest)?;
        let (point_v, rest) = CurvePoint::take(rest)?;
        let signature = CurveScalar::take_last(rest)?;
        Some(Self {
            params,
            point_e,
            point_v,
            signature,
        })
    }
}

impl Capsule {
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
        pk: &UmbralPublicKey,
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

        let shared_key = &pk.to_point() * &(&priv_r + &priv_u);

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
    pub fn open_reencrypted(
        &self,
        receiving_sk: &UmbralSecretKey,
        delegating_pk: &UmbralPublicKey,
        cfrags: &[CapsuleFrag],
    ) -> GenericArray<u8, PointSize> {
        let pub_key = UmbralPublicKey::from_secret_key(receiving_sk).to_point();

        let precursor = cfrags[0].precursor;
        let dh_point = &precursor * &receiving_sk.to_secret_scalar();

        // Combination of CFrags via Shamir's Secret Sharing reconstruction
        let points = [precursor, pub_key, dh_point];
        let mut lc = Vec::<CurveScalar>::with_capacity(cfrags.len());
        for cfrag in cfrags {
            let coeff = ScalarDigest::new()
                .chain_points(&points)
                .chain_bytes(X_COORDINATE)
                .chain_scalar(&cfrag.kfrag_id)
                .finalize();
            lc.push(coeff);
        }

        let mut e_prime = CurvePoint::identity();
        let mut v_prime = CurvePoint::identity();
        for (i, cfrag) in (&cfrags).iter().enumerate() {
            assert!(precursor == cfrag.precursor);
            let lambda_i = lambda_coeff(&lc, i);
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

        let orig_pub_key = delegating_pk.to_point();

        assert!(&orig_pub_key * &(&s * &d.invert().unwrap()) == &(&e_prime * &h) + &v_prime);
        //    raise GenericUmbralError()

        let shared_key = &(&e_prime + &v_prime) * &d;
        shared_key.to_array()
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
