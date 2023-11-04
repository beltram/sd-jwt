use crate::core::disclosure::Disclosure;
use crate::{crypto::CryptoBackend, error::SdjResult};

// TODO: turn generic again when RustRover stops 🤬
impl Disclosure {
    /// Creates a new object disclosure.
    pub fn try_new_object(backend: &mut CryptoBackend, name: String, value: serde_json::Value) -> SdjResult<Self> {
        let salt = backend.new_salt()?;
        Ok(Self::Object {
            salt,
            name,
            value,
            hasher: core::marker::PhantomData,
        })
    }

    /// Creates a new array disclosure.
    pub fn try_new_array(backend: &mut CryptoBackend, value: serde_json::Value) -> SdjResult<Self> {
        let salt = backend.new_salt()?;
        Ok(Self::Array {
            salt,
            value,
            hasher: core::marker::PhantomData,
        })
    }
}
