use crate::prelude::{SdjError, SdjResult};
use jwt_simple::prelude::*;

use super::{TryFromJwk, TryIntoJwk};

impl TryIntoJwk for RS256PublicKey {
    fn try_into_jwk(self) -> SdjResult<Jwk> {
        let c = self.to_components();
        let e = base64_simd::URL_SAFE_NO_PAD.encode_type::<String>(c.e);
        let n = base64_simd::URL_SAFE_NO_PAD.encode_type::<String>(c.n);
        Ok(Jwk {
            common: CommonParameters::default(),
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                e,
                n,
            }),
        })
    }
}

impl TryFromJwk for RS256PublicKey {
    fn try_from_jwk(jwk: &Jwk) -> SdjResult<Self> {
        Ok(match &jwk.algorithm {
            AlgorithmParameters::RSA(RSAKeyParameters { e, n, .. }) => {
                let e = base64_simd::STANDARD_NO_PAD.decode_to_vec(e)?;
                let n = base64_simd::STANDARD_NO_PAD.decode_to_vec(n)?;
                RS256PublicKey::from_components(&n, &e)?
            }
            _ => return Err(SdjError::InvalidJwk),
        })
    }
}
