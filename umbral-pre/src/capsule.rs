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

/// Encapsulated symmetric key used to encrypt the plaintext.
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
        Self::new_verified(params, point_e, point_v, signature)
    }
}

impl Capsule {
    pub(crate) fn new_verified(
        params: UmbralParameters,
        point_e: CurvePoint,
        point_v: CurvePoint,
        signature: CurveScalar,
    ) -> Option<Self> {
        let capsule = Self {
            params,
            point_e,
            point_v,
            signature,
        };
        match capsule.verify() {
            false => None,
            true => Some(capsule),
        }
    }

    /// Verifies the integrity of the capsule.
    fn verify(&self) -> bool {
        let g = CurvePoint::generator();
        let h = ScalarDigest::new()
            .chain_point(&self.point_e)
            .chain_point(&self.point_v)
            .finalize();
        &g * &self.signature == &self.point_v + &(&self.point_e * &h)
    }

    /// Generates a symmetric key and its associated KEM ciphertext
    pub(crate) fn from_pubkey(
        params: &UmbralParameters,
        pk: &UmbralPublicKey,
    ) -> (Capsule, CurvePoint) {
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

        (capsule, shared_key)
    }

    /// Derive the same symmetric key
    pub(crate) fn open_original(&self, private_key: &UmbralSecretKey) -> CurvePoint {
        &(&self.point_e + &self.point_v) * &private_key.to_secret_scalar()
    }

    #[allow(clippy::many_single_char_names)]
    pub(crate) fn open_reencrypted(
        &self,
        receiving_sk: &UmbralSecretKey,
        delegating_pk: &UmbralPublicKey,
        cfrags: &[CapsuleFrag],
    ) -> Option<CurvePoint> {
        if cfrags.is_empty() {
            return None;
        }

        // avoiding the panic branch that happens during normal array addressing
        let precursor = cfrags.get(0)?.precursor;

        if !cfrags.iter().all(|cfrag| cfrag.precursor == precursor) {
            return None;
        }

        let pub_key = UmbralPublicKey::from_secret_key(receiving_sk).to_point();
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
            let lambda_i = lambda_coeff(&lc, i)?;
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

        // Have to convert from subtle::CtOption here.
        let inv_d_opt: Option<CurveScalar> = d.invert().into();
        let inv_d = inv_d_opt?;

        if &orig_pub_key * &(&s * &inv_d) != &(&e_prime * &h) + &v_prime {
            return None;
        }

        let shared_key = &(&e_prime + &v_prime) * &d;
        Some(shared_key)
    }
}

fn lambda_coeff(xs: &[CurveScalar], i: usize) -> Option<CurveScalar> {
    let mut res = CurveScalar::one();
    for j in 0..xs.len() {
        if j != i {
            let xs_i = xs.get(i)?;
            let xs_j = xs.get(j)?;
            let inv_diff_opt: Option<CurveScalar> = (xs_j - xs_i).invert().into();
            let inv_diff = inv_diff_opt?;
            res = &(&res * xs_j) * &inv_diff;
        }
    }
    Some(res)
}
