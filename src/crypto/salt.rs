use crate::crypto::error::{CryptoError, CryptoResult};

/// Recommended default minimum length
pub const DEFAULT_SALT_SIZE: usize = 128 / 8;

/// Security considerations:
///
/// * The security model that conceals the plaintext claims relies on the fact that salts not
/// revealed to an attacker cannot be learned or guessed by the attacker, even if other salts
/// have been revealed. It is vitally important to adhere to this principle. As such, each salt
/// MUST be created in such a manner that it is cryptographically random, long enough, and has
/// high entropy that it is not practical for the attacker to guess. A new salt MUST be chosen
/// for each claim independently from other salts.
///
/// * The RECOMMENDED minimum length of the randomly-generated portion of the salt is 128 bits.
/// The Issuer MUST ensure that a new salt value is chosen for each claim, including when the
/// same claim name occurs at different places in the structure of the SD-JWT. This can be seen
/// in Example 3 in the Appendix, where multiple claims with the name type appear, but each of
/// them has a different salt.
///
/// See also: Section [9.3](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-9.3)
/// & [9.4](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-9.4)
#[derive(Debug, Clone, Eq, PartialEq)] // TODO: ct eq
pub struct Salt<const SIZE: usize = DEFAULT_SALT_SIZE>([u8; SIZE]);

#[cfg(feature = "issuer")]
impl<const SIZE: usize> Salt<SIZE> {
    pub fn try_new(rng: &mut rand_chacha::ChaCha20Rng) -> CryptoResult<Self> {
        use rand_chacha::rand_core::RngCore as _;
        let mut bytes = [0u8; SIZE];
        if bytes.len() < DEFAULT_SALT_SIZE {
            return Err(CryptoError::SaltTooSmall);
        }
        rng.try_fill_bytes(&mut bytes)?;
        Ok(Self(bytes))
    }
}

#[cfg(feature = "issuer")]
impl serde::Serialize for Salt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl ToString for Salt {
    fn to_string(&self) -> String {
        use base64ct::Encoding as _;
        base64ct::Base64UrlUnpadded::encode_string(&self.0)
    }
}

impl<const SIZE: usize> std::str::FromStr for Salt<SIZE> {
    type Err = CryptoError;

    fn from_str(s: &str) -> CryptoResult<Self> {
        let bytes = base64_simd::URL_SAFE_NO_PAD.decode_to_vec(s)?;
        let bytes = bytes.try_into().map_err(|_| CryptoError::InvalidSalt)?;
        Ok(Self(bytes))
    }
}

impl<const SIZE: usize> std::ops::Deref for Salt<SIZE> {
    type Target = [u8; SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn should_fail_when_size_too_small() {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        assert!(matches!(
            Salt::<15>::try_new(&mut rng).unwrap_err(),
            CryptoError::SaltTooSmall
        ));
    }
}
