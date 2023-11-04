use jwt_simple::prelude::{
    ECDSAP256KeyPairLike, ECDSAP384KeyPairLike, ES256KeyPair, ES384KeyPair, Ed25519KeyPair, EdDSAKeyPairLike,
};

use crate::{core::jws::Jws, error::SdjResult, issuer::JwtPayload, prelude::JwsAlgorithm};

impl Jws {
    pub(super) fn try_new(payload: JwtPayload, alg: JwsAlgorithm, key_pair: &str) -> SdjResult<Self> {
        let claims = jwt_simple::claims::JWTClaims {
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer: None,
            subject: None,
            audiences: None,
            jwt_id: None,
            nonce: None,
            custom: payload,
        };

        Ok(match alg {
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(key_pair)?.sign(claims)?,
            JwsAlgorithm::P256 => ES256KeyPair::from_pem(key_pair)?.sign(claims)?,
            JwsAlgorithm::P384 => ES384KeyPair::from_pem(key_pair)?.sign(claims)?,
        }
        .into())
    }
}
