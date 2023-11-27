use crate::prelude::SdjResult;
use jwt_simple::prelude::Jwk;

mod ecdsa;
mod eddsa;
mod rsa;

// TODO: improve by removing allocations

/// From json to JWK
pub trait TryIntoJwk {
    /// str -> JWK
    fn try_into_jwk(self) -> SdjResult<Jwk>;
}

/// From JWK to json
pub trait TryFromJwk
where
    Self: Sized,
{
    /// JWK -> str
    fn try_from_jwk(jwk: &Jwk) -> SdjResult<Self>;
}
