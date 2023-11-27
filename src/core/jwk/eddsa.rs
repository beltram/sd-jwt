use crate::{
    crypto::sign::JwsEdAlgorithm,
    prelude::{SdjError, SdjResult},
};
use jwt_simple::prelude::*;

use super::{TryFromJwk, TryIntoJwk};

impl TryFromJwk for Ed25519PublicKey {
    fn try_from_jwk(jwk: &Jwk) -> SdjResult<Self> {
        Ok(match &jwk.algorithm {
            AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters { x, .. }) => {
                let x = base64_simd::STANDARD_NO_PAD.decode_to_vec(x.as_bytes())?;
                Ed25519PublicKey::from_bytes(&x)?
            }
            _ => return Err(SdjError::InvalidJwk),
        })
    }
}

impl TryIntoJwk for Ed25519PublicKey {
    fn try_into_jwk(self) -> SdjResult<Jwk> {
        let alg = JwsEdAlgorithm::Ed25519;
        let x = base64_simd::URL_SAFE_NO_PAD.encode_type::<String>(self.to_bytes());
        Ok(Jwk {
            common: CommonParameters::default(),
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: alg.kty(),
                curve: alg.curve(),
                x,
            }),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use jwt_simple::prelude::*;
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod ed25519 {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_convert_key_into_jwk() {
            let key = Ed25519KeyPair::generate().public_key();
            let pk = Ed25519PublicKey::from_pem(&key.to_pem()).unwrap();
            let jwk = Ed25519PublicKey::try_into_jwk(pk).unwrap();
            let is_valid = |p: &OctetKeyPairParameters| {
                p.key_type == OctetKeyPairType::OctetKeyPair && p.curve == EdwardCurve::Ed25519
            };
            assert!(matches!(jwk.algorithm, AlgorithmParameters::OctetKeyPair(p) if is_valid(&p)));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_convert_jwk_into_key() {
            let original = Ed25519KeyPair::generate().public_key();
            let jwk = original.clone().try_into_jwk().unwrap();
            let new_key = Ed25519PublicKey::try_from_jwk(&jwk).unwrap();
            assert_eq!(original.to_bytes(), new_key.to_bytes())
        }
    }
}
