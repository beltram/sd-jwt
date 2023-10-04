use crate::{crypto::CryptoBackend, error::SdjResult};

// TODO: turn generic again when RustRover stops 🤬
// impl<'a, Hash: digest::Digest, const SALT_SIZE: usize> Disclosure<'a, Hash, SALT_SIZE> {
impl crate::core::disclosure::Disclosure<sha2::Sha256, 16> {
    /// Creates a new disclosure.
    pub fn try_new(backend: &mut CryptoBackend, name: Option<String>, value: serde_json::Value) -> SdjResult<Self> {
        let salt = backend.new_salt()?;
        Ok(Self {
            salt,
            name,
            value,
            hasher: core::marker::PhantomData,
        })
    }

    pub fn build(&self) -> SdjResult<String> {
        let Self { salt, name, value, .. } = self;
        let salt = salt.to_string();
        let utf8_encoded = if let Some(name) = name {
            format!("[\"{salt}\", \"{name}\", {}]", serde_json::to_string(&value)?)
        } else {
            format!("[\"{salt}\", {}]", serde_json::to_string(&value)?)
        };

        // this encoding might be vulnerable to side-channel attacks revealing the content being
        // encoded which should not be leaked
        use base64ct::Encoding as _;
        let b64_encoded = base64ct::Base64UrlUnpadded::encode_string(utf8_encoded.as_bytes());
        Ok(b64_encoded)
    }
}
