use crate::core::jws::Jws;
use crate::error::SdjResult;
use crate::issuer::JwtPayload;
use jwt_simple::prelude::{Ed25519KeyPair, EdDSAKeyPairLike};

impl Jws {
    pub(super) fn try_new(payload: JwtPayload) -> SdjResult<Self> {
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

        let kp = Ed25519KeyPair::generate();
        let jws = kp.sign(claims)?;

        Ok(jws.into())
    }
}
