use crate::cfrags::CapsuleFrag;
use crate::constants::{const_non_interactive, const_x_coordinate};
use crate::curve::{
    curve_generator, point_to_bytes, random_scalar, scalar_to_bytes, CurvePoint, CurvePointSize,
    CurveScalar, CurveScalarSize,
};
use crate::keys::{UmbralPrivateKey, UmbralPublicKey};
use crate::kfrags::KFrag;
use crate::params::UmbralParameters;
use crate::random_oracles::hash_to_scalar;
use crate::utils::lambda_coeff;

#[cfg(feature = "std")]
use std::vec::Vec;

use core::ops::Add;
use generic_array::sequence::Concat;
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

#[derive(Clone, Copy, Debug)]
pub struct Capsule {
    pub params: UmbralParameters,
    pub point_e: CurvePoint,
    pub point_v: CurvePoint,
    pub bn_sig: CurveScalar,
}

type CapsuleSize =
    <<CurvePointSize as Add<CurvePointSize>>::Output as Add<CurveScalarSize>>::Output;

impl Capsule {
    pub fn new(
        params: &UmbralParameters,
        point_e: &CurvePoint,
        point_v: &CurvePoint,
        bn_sig: &CurveScalar,
    ) -> Self {
        let res = Self {
            params: *params,
            point_e: *point_e,
            point_v: *point_v,
            bn_sig: *bn_sig,
        };
        res
    }

    pub fn to_bytes(&self) -> GenericArray<u8, CapsuleSize> {
        point_to_bytes(&self.point_e)
            .concat(point_to_bytes(&self.point_v))
            .concat(scalar_to_bytes(&self.bn_sig))
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
        &g * &self.bn_sig == &self.point_v + &(&self.point_e * &h)
    }

    /// Generates a symmetric key and its associated KEM ciphertext
    // TODO: might as well return a GenericArray instead of a point,
    // it's going to be hashed anyway.
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

        let shared_key = &(alice_pubkey.point_key) * &(&priv_r + &priv_u);

        let capsule = Self {
            params: *params,
            point_e: pub_r,
            point_v: pub_u,
            bn_sig: s,
        };

        (capsule, point_to_bytes(&shared_key))
    }

    /// Derive the same symmetric key
    pub fn open_original(
        &self,
        private_key: &UmbralPrivateKey,
    ) -> GenericArray<u8, CurvePointSize> {
        // TODO: capsule should be verified on creation
        //if not capsule.verify():
        //    # Check correctness of original ciphertext
        //    raise capsule.NotValid("Capsule verification failed.")

        let shared_key = (&self.point_e + &self.point_v) * &private_key.bn_key;
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
        let pub_key = receiving_privkey.get_pubkey().point_key;
        let priv_key = receiving_privkey.bn_key;

        let precursor = cfrags[0].point_precursor;
        let dh_point = &precursor * &priv_key;

        // Combination of CFrags via Shamir's Secret Sharing reconstruction
        let mut xs = Vec::<CurveScalar>::with_capacity(cfrags.len());
        for (_i, cfrag) in cfrags.iter().enumerate() {
            let customization_string =
                const_x_coordinate().concat(scalar_to_bytes(&cfrag.kfrag_id));
            xs.push(hash_to_scalar(
                &[precursor, pub_key, dh_point],
                Some(&customization_string),
            ));
        }

        let mut e_prime = CurvePoint::identity();
        let mut v_prime = CurvePoint::identity();
        for (cfrag, x) in (&cfrags).iter().zip((&xs).iter()) {
            assert!(precursor == cfrag.point_precursor);
            let lambda_i = lambda_coeff(&x, &xs);
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
        let s = self.bn_sig;
        let h = hash_to_scalar(&[e, v], None);

        let orig_pub_key = delegating_key.point_key;

        assert!(&orig_pub_key * &(&s * &d.invert().unwrap()) == &(&e_prime * &h) + &v_prime);
        //    raise GenericUmbralError()

        let shared_key = (&e_prime + &v_prime) * &d;
        point_to_bytes(&shared_key)
    }

    /// Derive the same symmetric encapsulated_key
    pub fn open_reencrypted_heapless<Threshold: ArrayLength<CurveScalar> + Unsigned>(
        &self,
        receiving_privkey: &UmbralPrivateKey,
        delegating_key: &UmbralPublicKey,
        cfrags: &[CapsuleFrag],
    ) -> GenericArray<u8, CurvePointSize> {
        let pub_key = receiving_privkey.get_pubkey().point_key;
        let priv_key = receiving_privkey.bn_key;

        let precursor = cfrags[0].point_precursor;
        let dh_point = &precursor * &priv_key;

        // Combination of CFrags via Shamir's Secret Sharing reconstruction
        let mut xs = GenericArray::<CurveScalar, Threshold>::default();
        for (i, cfrag) in cfrags.iter().enumerate() {
            let customization_string =
                const_x_coordinate().concat(scalar_to_bytes(&cfrag.kfrag_id));
            xs[i] = hash_to_scalar(&[precursor, pub_key, dh_point], Some(&customization_string));
        }

        let mut e_prime = CurvePoint::identity();
        let mut v_prime = CurvePoint::identity();
        for (cfrag, x) in (&cfrags).iter().zip((&xs).iter()) {
            assert!(precursor == cfrag.point_precursor);
            let lambda_i = lambda_coeff(&x, &xs);
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
        let s = self.bn_sig;
        let h = hash_to_scalar(&[e, v], None);

        let orig_pub_key = delegating_key.point_key;

        assert!(&orig_pub_key * &(&s * &d.invert().unwrap()) == &(&e_prime * &h) + &v_prime);
        //    raise GenericUmbralError()

        let shared_key = (&e_prime + &v_prime) * &d;
        point_to_bytes(&shared_key)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PreparedCapsule {
    pub capsule: Capsule,
    pub delegating_key: UmbralPublicKey,
    pub receiving_key: UmbralPublicKey,
    pub verifying_key: UmbralPublicKey,
}

impl PreparedCapsule {
    pub fn verify_cfrag(&self, cfrag: &CapsuleFrag) -> bool {
        cfrag.verify_correctness(
            &self.capsule,
            &self.delegating_key,
            &self.receiving_key,
            &self.verifying_key,
        )
    }

    pub fn verify_kfrag(&self, kfrag: &KFrag) -> bool {
        kfrag.verify(
            &self.verifying_key,
            Some(&self.delegating_key),
            Some(&self.receiving_key),
        )
    }

    pub fn reencrypt(
        &self,
        kfrag: &KFrag,
        metadata: Option<&[u8]>,
        verify_kfrag: bool,
    ) -> Option<CapsuleFrag> {
        // TODO: verify on creation?
        //if not prepared_capsule.verify():
        //    raise Capsule.NotValid

        if verify_kfrag {
            if !self.verify_kfrag(&kfrag) {
                return None;
            }
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
