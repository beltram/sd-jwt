use crate::error::SdjError;
use crate::prelude::{JwsAlgorithm, SdjResult};
use jwt_simple::prelude::{
    ECDSAP256PublicKeyLike, ECDSAP384PublicKeyLike, ES256PublicKey, ES384PublicKey, Ed25519PublicKey,
    EdDSAPublicKeyLike, JWTClaims,
};
use serde_json::Value;

#[derive(Debug, Clone, derive_more::AsRef, derive_more::Deref, derive_more::From, derive_more::Into)]
pub struct Jws(String);

impl Jws {
    pub fn try_read_payload(&self, alg: JwsAlgorithm, verify_key: &str) -> SdjResult<JWTClaims<Value>> {
        // TODO:
        let verification_options = None;
        match alg {
            JwsAlgorithm::Ed25519 => {
                Ed25519PublicKey::from_pem(verify_key)?.verify_token::<Value>(self, verification_options)
            }
            JwsAlgorithm::P256 => {
                ES256PublicKey::from_pem(verify_key)?.verify_token::<Value>(self, verification_options)
            }
            JwsAlgorithm::P384 => {
                ES384PublicKey::from_pem(verify_key)?.verify_token::<Value>(self, verification_options)
            }
        }
        .map_err(|_| SdjError::InvalidJwt)
    }
}
