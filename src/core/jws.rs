use crate::prelude::{JwsAlgorithm, SdjError, SdjResult};
use jwt_simple::prelude::{
    ECDSAP256PublicKeyLike, ECDSAP384PublicKeyLike, ES256PublicKey, ES384PublicKey, Ed25519PublicKey,
    EdDSAPublicKeyLike, JWTClaims,
};
use serde_json::Value;

#[derive(Debug, Clone, derive_more::AsRef, derive_more::Deref, derive_more::From, derive_more::Into)]
pub struct Jws(String);

impl Jws {
    pub fn try_read_payload(&self, alg: JwsAlgorithm, verify_key: &str) -> SdjResult<Value> {
        // TODO:
        let verification_options = None;
        let claims = match alg {
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
        .map_err(|_| SdjError::InvalidJwt)?;
        Ok(Self::unfold_claims(claims))
    }

    /// Given wrapper struct ([JWTClaims]) which contains some standard JWT claims
    /// extract them from here to give a simple flat [Value] and have a loosely coupled API
    /// (not depending on [jwt_simple])
    fn unfold_claims(claims: JWTClaims<Value>) -> Value {
        claims.custom
    }

    #[cfg(any(test, feature = "e2e-test"))]
    pub fn to_parts(&self) -> (&str, &str, &str) {
        let parts: [&str; 3] = self.split('.').collect::<Vec<_>>().try_into().unwrap();
        let [header, payload, signature] = parts;
        (header, payload, signature)
    }
}
