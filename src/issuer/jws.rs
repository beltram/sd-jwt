use jwt_simple::prelude::{
    ECDSAP256KeyPairLike, ECDSAP384KeyPairLike, ES256KeyPair, ES384KeyPair, Ed25519KeyPair, EdDSAKeyPairLike, JWTHeader,
};

use crate::{
    core::jws::Jws,
    error::SdjResult,
    issuer::{std::StdClaims, JwtPayload},
    prelude::JwsAlgorithm,
};

impl Jws {
    const TYP: &'static str = "example+sd-jwt";

    pub(super) fn try_new(
        payload: JwtPayload,
        std_claims: StdClaims,
        alg: JwsAlgorithm,
        key_pair: &str,
    ) -> SdjResult<Self> {
        let header = Self::new_header(alg);
        let claims = std_claims.to_inner_claims(payload);

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
