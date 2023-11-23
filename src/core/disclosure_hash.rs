use crate::{core::disclosure::Disclosure, error::SdjResult};
use serde::Serialize;
use serde_json::{json, Value};

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
        let json = match self {
            Disclosure::Object { salt, name, value, .. } => json!([salt, name, value]),
            Disclosure::Array { salt, value, .. } => json!([salt, value]),
        };

        // this encoding might be vulnerable to side-channel attacks revealing the content being
        // encoded which should not be leaked
        use base64ct::Encoding as _;
        let b64_encoded = base64ct::Base64UrlUnpadded::encode_string(&Self::serialize_to_json_string(json)?);
        Ok(b64_encoded)
    }

    #[cfg(not(feature = "e2e-test"))]
    fn serialize_to_json_string(json: Value) -> SdjResult<Vec<u8>> {
        Ok(serde_json::to_vec(&json)?)
    }

    #[cfg(feature = "e2e-test")]
    fn serialize_to_json_string(json: Value) -> SdjResult<Vec<u8>> {
        let mut buf = vec![];
        let python_fmt = serde_json_python_formatter::PythonFormatter::default();
        let mut serializer = serde_json::Serializer::with_formatter(&mut buf, python_fmt);
        json.serialize(&mut serializer)?;
        Ok(buf)
    }
}
