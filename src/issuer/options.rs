use crate::crypto::hash::HashAlgorithm;
use crate::prelude::JwsAlgorithm;

/// Configuration of the issued SD-JWT
#[derive(Debug, Clone)]
pub struct IssuerOptions {
    /// Hash algorithm used for hashing [crate::core::disclosure::Disclosure]s
    pub hash_alg: HashAlgorithm,
    /// Signature algorithm of the JWS
    pub sign_alg: JwsAlgorithm,
}

#[allow(clippy::derivable_impls)]
impl Default for IssuerOptions {
    fn default() -> Self {
        Self {
            hash_alg: Default::default(),
            sign_alg: Default::default(),
        }
    }
}
