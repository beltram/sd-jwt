use jwt_simple::prelude::*;

use crate::{core::jws::Jws, error::SdjResult, issuer::JwtPayload, prelude::JwsAlgorithm};

impl Jws {
    const TYP: &'static str = "example+sd-jwt";

    pub(super) fn try_new(payload: JwtPayload, alg: JwsAlgorithm, key_pair: &str) -> SdjResult<Self> {
        let header = Self::new_header(alg);
        let claims = JWTClaims {
            custom: payload,
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer: None,
            subject: None,
            audiences: None,
            jwt_id: None,
            nonce: None,
        };

        Ok(match alg {
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(key_pair)?.sign_with_header(Some(claims), header)?,
            JwsAlgorithm::P256 => ES256KeyPair::from_pem(key_pair)?.sign_with_header(Some(claims), header)?,
            JwsAlgorithm::P384 => ES384KeyPair::from_pem(key_pair)?.sign_with_header(Some(claims), header)?,
        }
        .into())
    }

    fn new_header(alg: JwsAlgorithm) -> JWTHeader {
        JWTHeader {
            algorithm: alg.to_string(),
            signature_type: Some(Self::TYP.to_string()),
            ..Default::default()
        }
    }
}
