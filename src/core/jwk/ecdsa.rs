use crate::{crypto::sign::JwsEcAlgorithm, error::SdjError, prelude::SdjResult};
use jwt_simple::prelude::*;

use super::{TryFromJwk, TryIntoJwk};

impl TryIntoJwk for ES256PublicKey {
    fn try_into_jwk(self) -> SdjResult<Jwk> {
        AnyEcPublicKey(JwsEcAlgorithm::P256, self.public_key().to_bytes_uncompressed()).try_into_jwk()
    }
}

impl TryFromJwk for ES256PublicKey {
    fn try_from_jwk(jwk: &Jwk) -> SdjResult<Self> {
        Ok(match &jwk.algorithm {
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x,
                y,
            }) => {
                let x = base64_simd::STANDARD_NO_PAD.decode_to_vec(x.as_bytes())?;
                let y = base64_simd::STANDARD_NO_PAD.decode_to_vec(y.as_bytes())?;
                let point =
                    p256::EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
                ES256PublicKey::from_bytes(point.as_bytes())?
            }
            _ => return Err(SdjError::InvalidJwk),
        })
    }
}

impl TryIntoJwk for ES384PublicKey {
    fn try_into_jwk(self) -> SdjResult<Jwk> {
        AnyEcPublicKey(JwsEcAlgorithm::P384, self.public_key().to_bytes_uncompressed()).try_into_jwk()
    }
}

impl TryFromJwk for ES384PublicKey {
    fn try_from_jwk(jwk: &Jwk) -> SdjResult<Self> {
        Ok(match &jwk.algorithm {
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P384,
                x,
                y,
            }) => {
                let x = base64_simd::STANDARD_NO_PAD.decode_to_vec(x.as_bytes())?;
                let y = base64_simd::STANDARD_NO_PAD.decode_to_vec(y.as_bytes())?;
                let point =
                    p384::EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
                ES384PublicKey::from_bytes(point.as_bytes())?
            }
            _ => return Err(SdjError::InvalidJwk),
        })
    }
}

/// For factorizing common elliptic curve operations
struct AnyEcPublicKey(JwsEcAlgorithm, Vec<u8>);

impl TryIntoJwk for AnyEcPublicKey {
    fn try_into_jwk(self) -> SdjResult<Jwk> {
        let Self(alg, bytes) = self;
        let (x, y) = match alg {
            JwsEcAlgorithm::P256 => {
                let point = p256::EncodedPoint::from_bytes(bytes)?;
                let x = point.x().ok_or(SdjError::InvalidPublicKey)?;
                let x = base64_simd::URL_SAFE_NO_PAD.encode_type::<String>(x);
                let y = point.y().ok_or(SdjError::InvalidPublicKey)?;
                let y = base64_simd::URL_SAFE_NO_PAD.encode_type::<String>(y);
                (x, y)
            }
            JwsEcAlgorithm::P384 => {
                let point = p384::EncodedPoint::from_bytes(bytes)?;
                let x = point.x().ok_or(SdjError::InvalidPublicKey)?;
                let x = base64_simd::URL_SAFE_NO_PAD.encode_type::<String>(x);
                let y = point.y().ok_or(SdjError::InvalidPublicKey)?;
                let y = base64_simd::URL_SAFE_NO_PAD.encode_type::<String>(y);
                (x, y)
            }
            _ => return Err(SdjError::ImplementationError),
        };
        Ok(Jwk {
            common: CommonParameters::default(),
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: alg.kty(),
                curve: alg.curve(),
                x,
                y,
            }),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod p256 {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_convert_p256_key_into_jwk() {
            let key = ES256KeyPair::generate().public_key();
            let pk = ES256PublicKey::from_pem(key.to_pem().unwrap().as_str()).unwrap();
            let jwk = ES256PublicKey::try_into_jwk(pk).unwrap();
            let is_valid = |p: &EllipticCurveKeyParameters| {
                p.key_type == EllipticCurveKeyType::EC && p.curve == EllipticCurve::P256
            };
            assert!(matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(p) if is_valid(&p)));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_convert_p256_jwk_into_key() {
            let original = ES256KeyPair::generate().public_key();
            let jwk = original.clone().try_into_jwk().unwrap();
            let new_key = ES256PublicKey::try_from_jwk(&jwk).unwrap();
            assert_eq!(original.to_bytes(), new_key.to_bytes());
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_converting_jwk_into_key_when_wrong_size() {
            let original = ES256KeyPair::generate().public_key();
            let jwk = original.try_into_jwk().unwrap();
            // trying from the wrong key size
            let result = ES384PublicKey::try_from_jwk(&jwk);
            assert!(matches!(result.unwrap_err(), SdjError::InvalidJwk));
        }
    }

    mod p384 {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_convert_p384_key_into_jwk() {
            let key = ES384KeyPair::generate().public_key();
            let pk = ES384PublicKey::from_pem(key.to_pem().unwrap().as_str()).unwrap();
            let jwk = ES384PublicKey::try_into_jwk(pk).unwrap();
            let is_valid = |p: &EllipticCurveKeyParameters| {
                p.key_type == EllipticCurveKeyType::EC && p.curve == EllipticCurve::P384
            };
            assert!(matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(p) if is_valid(&p)));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_convert_p384_jwk_into_key() {
            let original = ES384KeyPair::generate().public_key();
            let jwk = original.clone().try_into_jwk().unwrap();
            let new_key = ES384PublicKey::try_from_jwk(&jwk).unwrap();
            assert_eq!(original.to_bytes(), new_key.to_bytes());
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_converting_jwk_into_key_when_wrong_size() {
            let original = ES384KeyPair::generate().public_key();
            let jwk = original.try_into_jwk().unwrap();
            // trying from the wrong key size
            let result = ES384PublicKey::try_from_jwk(&jwk);
            assert!(matches!(result.unwrap_err(), SdjError::InvalidJwk));
        }
    }
}
