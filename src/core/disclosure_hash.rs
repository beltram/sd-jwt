/// A hashed (by [crate::prelude::Issuer]) [crate::core::disclosure::Disclosure] to be verified
/// by a [crate::prelude::Verifier]
#[derive(PartialEq, derive_more::From, derive_more::Into, derive_more::AsRef, serde::Serialize, serde::Deserialize)]
pub struct DisclosureHash(String);

#[cfg(feature = "issuer")]
impl crate::core::disclosure::Disclosure<sha2::Sha256, 16> {
    pub fn hash(&self) -> crate::error::SdjResult<DisclosureHash> {
        // let mut hasher = Hash::new();
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let input = self.build()?;
        hasher.update(input.as_bytes());
        let hashed = hasher.finalize();
        let b64_encoded = base64_simd::URL_SAFE_NO_PAD.encode_to_string(hashed.as_slice());
        Ok(b64_encoded.into())
    }
}
