#[allow(dead_code)]
pub type SdjResult<T> = Result<T, SdjError>;

#[derive(thiserror::Error, Debug)]
pub enum SdjError {
    #[error(transparent)]
    CryptoError(#[from] crate::crypto::error::CryptoError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    YamlError(#[from] serde_yaml::Error),
    #[error(transparent)]
    Base64Error(#[from] base64_simd::Error),
    #[error(transparent)]
    JwtError(#[from] jwt_simple::Error),
    #[error("Invalid Json pointer error {0}")]
    JsonPointerError(String),
    #[error("Invalid Json pointer path {0}")]
    InvalidJsonPointerPath(String),
    #[error("Invalid format of the SD-Jwt")]
    InvalidSerializedSdJwt,
    #[error("Invalid JWT")]
    InvalidJwt,
    #[error("A user provider Json Pointer does not match a Disclosure")]
    UnknownDisclosure,
    #[error("Invalid Disclosure")]
    InvalidDisclosure,
    #[error("Invalid Holder selection")]
    InvalidHolderSelection,
    #[error("Unexpected internal error")]
    ImplementationError,
}
