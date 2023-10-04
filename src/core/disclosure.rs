use crate::crypto::{self, salt::Salt};

/// A combination of a salt, a cleartext claim name (present when the claim is a key-value pair and
/// absent when the claim is an array element), and a cleartext claim value, all of which are used to
/// calculate a digest for the respective claim.
///
/// See also: [RFC]
///
/// [RFC]: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.2
pub struct Disclosure<Hash: digest::Digest = sha2::Sha256, const SALT_SIZE: usize = { crypto::DEFAULT_SALT_SIZE }> {
    /// A salt value. MUST be a string. See Section
    /// [9.3](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-9.3)
    /// and Section [9.4](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-9.4)
    /// for security considerations. It is RECOMMENDED to base64url-encode minimum 128 bits of
    /// cryptographically secure pseudorandom data, producing a string. The salt value MUST be
    /// unique for each claim that is to be selectively disclosed. The Issuer MUST NOT disclose the
    /// salt value to any party other than the Holder.
    pub(crate) salt: Salt<SALT_SIZE>,
    /// The claim name, or key, as it would be used in a regular JWT body. The value MUST be a
    /// string.
    pub(crate) name: Option<String>,
    /// The claim value, as it would be used in a regular JWT body. The value MAY be of any type
    /// that is allowed in JSON, including numbers, strings, booleans, arrays, and objects.
    pub(crate) value: serde_json::Value,
    /// Marker
    pub(crate) hasher: core::marker::PhantomData<Hash>,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// See also: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.2.1
    #[test]
    fn should_pass_rfc_example_for_object() {
        // let (salt, name, value) = ("_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius");

        // TODO:
        /*let disclosure = Disclosure {
            salt: salt.parse::<Salt<17>>().unwrap(),
            name: Some(name),
            value: &serde_json::json!(value),
            hasher: core::marker::PhantomData::<sha2::Sha256>::default(),
        };
        assert_eq!(
            disclosure.build().unwrap(),
            "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0".to_string()
        );*/
    }

    /// See also: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.2.2
    #[test]
    fn should_pass_rfc_example_for_array() {
        let (salt, value) = ("lklxF5jMYlGTPUovMNIvCA", "FR");

        let disclosure = Disclosure {
            salt: salt.parse::<Salt<16>>().unwrap(),
            name: None,
            value: serde_json::json!(value),
            hasher: core::marker::PhantomData::<sha2::Sha256>::default(),
        };
        assert_eq!(
            disclosure.build().unwrap(),
            "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0".to_string()
        );
    }

    /// See also: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.3
    #[test]
    fn should_pass_rfc_example_for_hash() {
        let (salt, value) = ("lklxF5jMYlGTPUovMNIvCA", "FR");

        let disclosure = Disclosure {
            salt: salt.parse::<Salt<16>>().unwrap(),
            name: None,
            value: serde_json::json!(value),
            hasher: core::marker::PhantomData::<sha2::Sha256>::default(),
        };
        let hash: String = disclosure.hash().unwrap().into();
        assert_eq!(hash, "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs".to_string());
    }
}
