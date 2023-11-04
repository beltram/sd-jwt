//! Selective Disclosure JWTs

#[cfg(any(feature = "issuer", feature = "holder", feature = "verifier"))]
mod core;
#[cfg(any(feature = "issuer", feature = "holder", feature = "verifier"))]
mod crypto;
#[cfg(any(feature = "issuer", feature = "holder", feature = "verifier"))]
mod error;

#[cfg(feature = "holder")]
mod holder;
#[cfg(feature = "issuer")]
mod issuer;
#[cfg(feature = "verifier")]
mod verifier;

/// Marker trait for all instances involved in the flow
pub(crate) trait ThirdParty {}

pub mod prelude {
    #[cfg(any(feature = "issuer", feature = "holder", feature = "verifier"))]
    pub use crate::{
        core::sd_jwt::SDJwt,
        crypto::{hash::HashAlgorithm, sign::JwsAlgorithm},
        error::{SdjError, SdjResult},
    };

    #[cfg(feature = "issuer")]
    pub use crate::issuer::{input::InputClaimSet, options::IssuerOptions, Issuer};

    #[cfg(feature = "holder")]
    pub use crate::holder::Holder;

    #[cfg(feature = "verifier")]
    pub use crate::verifier::Verifier;
}
