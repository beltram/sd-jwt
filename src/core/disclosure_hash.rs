use crate::{core::disclosure::Disclosure, error::SdjResult};
use serde::Serialize;
use serde_json::json;

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
        let input = self.encode()?;
        hasher.update(input.as_bytes());
        let hashed = hasher.finalize();
        let b64_encoded = base64_simd::URL_SAFE_NO_PAD.encode_to_string(hashed.as_slice());
        Ok(b64_encoded.into())
    }

    pub fn encode(&self) -> SdjResult<String> {
        let mut buf = vec![];
        let python_fmt = serde_json_python_formatter::PythonFormatter::default();
        let mut serializer = serde_json::Serializer::with_formatter(&mut buf, python_fmt);

        match self {
            Disclosure::Object { salt, name, value, .. } => json!([salt, name, value]),
            Disclosure::Array { salt, value, .. } => json!([salt, value]),
        }
        .serialize(&mut serializer)?;
        let utf8_encoded = String::from_utf8(buf)?;

        // this encoding might be vulnerable to side-channel attacks revealing the content being
        // encoded which should not be leaked
        use base64ct::Encoding as _;
        let b64_encoded = base64ct::Base64UrlUnpadded::encode_string(utf8_encoded.as_bytes());
        Ok(b64_encoded)
    }
}
