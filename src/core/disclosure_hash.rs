use crate::{core::disclosure::Disclosure, error::SdjResult};

/// A hashed (by [crate::prelude::Issuer]) [Disclosure] to be verified
/// by a [crate::prelude::Verifier]
#[derive(
    PartialEq,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    derive_more::Deref,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct DisclosureHash(String);

impl Disclosure<sha2::Sha256, 16> {
    pub fn hash(&self) -> SdjResult<DisclosureHash> {
        // let mut hasher = Hash::new();
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let input = self.build()?;
        hasher.update(input.as_bytes());
        let hashed = hasher.finalize();
        let b64_encoded = base64_simd::URL_SAFE_NO_PAD.encode_to_string(hashed.as_slice());
        Ok(b64_encoded.into())
    }

    pub fn build(&self) -> SdjResult<String> {
        let utf8_encoded = match self {
            Disclosure::Object { salt, name, value, .. } => {
                let salt = salt.to_string();
                let value = serde_json::to_string(&value)?;
                format!("[\"{salt}\", \"{name}\", {value}]")
            }
            Disclosure::Array { salt, value, .. } => {
                let salt = salt.to_string();
                let value = serde_json::to_string(&value)?;
                format!("[\"{salt}\", {value}]")
            }
        };

        // this encoding might be vulnerable to side-channel attacks revealing the content being
        // encoded which should not be leaked
        use base64ct::Encoding as _;
        let b64_encoded = base64ct::Base64UrlUnpadded::encode_string(utf8_encoded.as_bytes());
        Ok(b64_encoded)
    }
}
