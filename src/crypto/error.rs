pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[cfg(feature = "issuer")]
    #[error(transparent)]
    RngError(#[from] rand_chacha::rand_core::Error),
    #[error("Lock is poisonned")]
    PoisonError,
    #[error("Salt size is below the recommended size (16)")]
    SaltTooSmall,
    #[error("Invalid salt")]
    InvalidSalt,
    #[error(transparent)]
    Base64Error(#[from] base64_simd::Error),
    #[error("Internal error: {0}")]
    ImplementationError(&'static str),
}
