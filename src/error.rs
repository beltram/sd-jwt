#[allow(dead_code)]
pub type SdjResult<T> = Result<T, SdjError>;

#[derive(thiserror::Error, Debug)]
pub enum SdjError {
    #[error(transparent)]
    CryptoError(#[from] crate::crypto::error::CryptoError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[cfg(any(feature = "issuer", feature = "verifier"))]
    #[error(transparent)]
    JwtError(#[from] jwt_simple::Error),
    #[error("Invalid Json pointer error {0}")]
    JsonPointerError(String),
    #[error("Unexpected internal error")]
    ImplementationError,
}
