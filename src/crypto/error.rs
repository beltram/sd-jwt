pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[cfg(feature = "issuer")]
    #[error(transparent)]
    RngError(#[from] rand_chacha::rand_core::Error),
    #[error("Lock is poisonned")]
    PoisonError,
    #[error("Internal error: {0}")]
    ImplementationError(&'static str),
    #[error("Salt size is below the recommended size (16)")]
    SaltTooSmall,
}
