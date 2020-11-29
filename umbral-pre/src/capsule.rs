use crate::capsule_frag::CapsuleFrag;
use crate::constants::{NON_INTERACTIVE, X_COORDINATE};
use crate::curve::{CurvePoint, CurveScalar, PublicKey, SecretKey};
use crate::hashing::ScalarDigest;
use crate::params::Parameters;
use crate::traits::SerializableToArray;

use alloc::vec::Vec;

use generic_array::sequence::Concat;
use generic_array::GenericArray;
use typenum::op;

/// Encapsulated symmetric key used to encrypt the plaintext.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Capsule {
    pub(crate) params: Parameters,
    pub(crate) point_e: CurvePoint,
    pub(crate) point_v: CurvePoint,
    pub(crate) signature: CurveScalar,
}

type ParametersSize = <Parameters as SerializableToArray>::Size;
type PointSize = <CurvePoint as SerializableToArray>::Size;
type ScalarSize = <CurveScalar as SerializableToArray>::Size;
type CapsuleSize = op!(ParametersSize + PointSize + PointSize + ScalarSize);

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
        let (params, rest) = Parameters::take(*arr)?;
        let (point_e, rest) = CurvePoint::take(rest)?;
        let (point_v, rest) = CurvePoint::take(rest)?;
        let signature = CurveScalar::take_last(rest)?;
        Self::new_verified(params, point_e, point_v, signature)
    }
}

impl Capsule {
    pub(crate) fn new_verified(
        params: Parameters,
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
    pub(crate) fn from_pubkey(params: &Parameters, pk: &PublicKey) -> (Capsule, CurvePoint) {
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
    pub(crate) fn open_original(&self, private_key: &SecretKey) -> CurvePoint {
        &(&self.point_e + &self.point_v) * &private_key.to_secret_scalar()
    }

    #[allow(clippy::many_single_char_names)]
    pub(crate) fn open_reencrypted(
        &self,
        receiving_sk: &SecretKey,
        delegating_pk: &PublicKey,
        cfrags: &[CapsuleFrag],
    ) -> Option<CurvePoint> {
        if cfrags.is_empty() {
            return None;
        }

        let precursor = cfrags[0].precursor;

        if !cfrags.iter().all(|cfrag| cfrag.precursor == precursor) {
            return None;
        }

        let pub_key = PublicKey::from_secret_key(receiving_sk).to_point();
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
            // There is a minuscule probability that two elements of `lc` are equal,
            // in which case we'd rather fail gracefully.
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
        // TODO: at the moment we cannot guarantee statically that the digest `d` is non-zero.
        // Technically, it is supposed to be non-zero by the choice of `precursor`,
        // but if is was somehow replaced by an incorrect value,
        // we'd rather fail gracefully than panic.
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
            let inv_diff_opt: Option<CurveScalar> = (&xs[j] - &xs[i]).invert().into();
            let inv_diff = inv_diff_opt?;
            res = &(&res * &xs[j]) * &inv_diff;
        }
    }
    Some(res)
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use super::Capsule;
    use crate::{
        encrypt, generate_kfrags, reencrypt, CapsuleFrag, Parameters, PublicKey, SecretKey,
        SerializableToArray,
    };

    #[test]
    fn test_serialize() {
        let params = Parameters::new();

        let delegating_sk = SecretKey::random();
        let delegating_pk = PublicKey::from_secret_key(&delegating_sk);

        let plaintext = b"peace at dawn";
        let (capsule, _ciphertext) = encrypt(&params, &delegating_pk, plaintext).unwrap();

        let capsule_arr = capsule.to_array();
        let capsule_back = Capsule::from_array(&capsule_arr).unwrap();
        assert_eq!(capsule, capsule_back);
    }

    #[test]
    fn test_open_reencrypted() {
        let params = Parameters::new();

        let delegating_sk = SecretKey::random();
        let delegating_pk = PublicKey::from_secret_key(&delegating_sk);

        let signing_sk = SecretKey::random();

        let receiving_sk = SecretKey::random();
        let receiving_pk = PublicKey::from_secret_key(&receiving_sk);

        let (capsule, key_seed) = Capsule::from_pubkey(&params, &delegating_pk);

        let kfrags = generate_kfrags(
            &params,
            &delegating_sk,
            &receiving_pk,
            &signing_sk,
            2,
            3,
            true,
            true,
        );

        let cfrags: Vec<CapsuleFrag> = kfrags
            .iter()
            .map(|kfrag| reencrypt(&capsule, &kfrag, None))
            .collect();

        let key_seed_reenc = capsule
            .open_reencrypted(&receiving_sk, &delegating_pk, &cfrags)
            .unwrap();
        assert_eq!(key_seed, key_seed_reenc);

        // Empty cfrag vector
        assert!(capsule
            .open_reencrypted(&receiving_sk, &delegating_pk, &[])
            .is_none());

        // Mismatched cfrags - each `generate_kfrags()` uses new randoms.
        let kfrags2 = generate_kfrags(
            &params,
            &delegating_sk,
            &receiving_pk,
            &signing_sk,
            2,
            3,
            true,
            true,
        );

        let cfrags2: Vec<CapsuleFrag> = kfrags2
            .iter()
            .map(|kfrag| reencrypt(&capsule, &kfrag, None))
            .collect();

        let mismatched_cfrags: Vec<CapsuleFrag> = cfrags[0..1]
            .iter()
            .cloned()
            .chain(cfrags2[1..2].iter().cloned())
            .collect();
        assert!(capsule
            .open_reencrypted(&receiving_sk, &delegating_pk, &mismatched_cfrags)
            .is_none());

        // Mismatched capsule
        let (capsule2, _key_seed) = Capsule::from_pubkey(&params, &delegating_pk);
        assert!(capsule2
            .open_reencrypted(&receiving_sk, &delegating_pk, &cfrags)
            .is_none());
    }
}
