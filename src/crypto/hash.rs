/// Hash Algorithm
/// See also:
/// * https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.8
/// * https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-9
/// * https://www.iana.org/assignments/named-information/named-information.xhtml
#[derive(Debug, Copy, Clone, Default)]
pub enum HashAlgorithm {
    #[allow(dead_code)]
    #[default]
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    /// Preferred for 32-bit platforms
    Blake2s256,
    /// Preferred for 64-bit platforms
    Blake2b256,
    /// Preferred for 64-bit platforms
    Blake2b512,
}

impl HashAlgorithm {
    pub fn to_jwt_claim(&self) -> &'static str {
        match self {
            HashAlgorithm::SHA256 => "sha-256",
            HashAlgorithm::SHA384 => "sha-384",
            HashAlgorithm::SHA512 => "sha-512",
            HashAlgorithm::SHA3_256 => "sha3-256",
            HashAlgorithm::SHA3_384 => "sha3-384",
            HashAlgorithm::SHA3_512 => "sha3-512",
            HashAlgorithm::Blake2s256 => "blake2s-256",
            HashAlgorithm::Blake2b256 => "blake2b-256",
            HashAlgorithm::Blake2b512 => "blake2b-512",
        }
    }
}
