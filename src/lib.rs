//! Selective Disclosure JWTs

mod crypto;
mod error;
mod holder;
mod issuer;
mod verifier;

/// Marker trait for all instances invlved in the flow
pub(crate) trait ThirdParty {}

pub struct SDJwt;

pub mod prelude {}
