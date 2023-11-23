use crate::{
    crypto::{self, salt::Salt},
    error::SdjError,
};

/// A combination of a salt, a cleartext claim name (present when the claim is a key-value pair and
/// absent when the claim is an array element), and a cleartext claim value, all of which are used to
/// calculate a digest for the respective claim.
///
/// See also: [RFC]
///
/// [RFC]: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.2
#[derive(Debug, Clone)]
pub enum Disclosure<Hash: digest::Digest = sha2::Sha256, const SALT_SIZE: usize = { crypto::DEFAULT_SALT_SIZE }> {
    Object {
        /// A salt value. MUST be a string. See Section
        /// [9.3](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-9.3)
        /// and Section [9.4](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-9.4)
        /// for security considerations. It is RECOMMENDED to base64url-encode minimum 128 bits of
        /// cryptographically secure pseudorandom data, producing a string. The salt value MUST be
        /// unique for each claim that is to be selectively disclosed. The Issuer MUST NOT disclose the
        /// salt value to any party other than the Holder.
        salt: Salt<SALT_SIZE>,
        /// The claim name, or key, as it would be used in a regular JWT body. The value MUST be a string.
        name: String,
        /// The claim value, as it would be used in a regular JWT body. The value MAY be of any type
        /// that is allowed in JSON, including numbers, strings, booleans, arrays, and objects.
        value: serde_json::Value,
        /// Marker
        hasher: core::marker::PhantomData<Hash>,
    },
    Array {
        /// A salt value. MUST be a string. See Section
        /// [9.3](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-9.3)
        /// and Section [9.4](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-9.4)
        /// for security considerations. It is RECOMMENDED to base64url-encode minimum 128 bits of
        /// cryptographically secure pseudorandom data, producing a string. The salt value MUST be
        /// unique for each claim that is to be selectively disclosed. The Issuer MUST NOT disclose the
        /// salt value to any party other than the Holder.
        salt: Salt<SALT_SIZE>,
        /// The claim value, as it would be used in a regular JWT body. The value MAY be of any type
        /// that is allowed in JSON, including numbers, strings, booleans, arrays, and objects.
        value: serde_json::Value,
        /// Marker
        hasher: core::marker::PhantomData<Hash>,
    },
}

impl Eq for Disclosure {}

impl PartialEq for Disclosure {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Object {
                    salt: s1,
                    name: n1,
                    value: v1,
                    ..
                },
                Self::Object {
                    salt: s2,
                    name: n2,
                    value: v2,
                    ..
                },
            ) => s1 == s2 && n1 == n2 && v1 == v2,
            (
                Self::Array {
                    salt: s1, value: v1, ..
                },
                Self::Array {
                    salt: s2, value: v2, ..
                },
            ) => s1 == s2 && v1 == v2,
            _ => false,
        }
    }
}

impl std::fmt::Display for Disclosure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Object { salt, name, value, .. } => {
                write!(f, "[\"{salt}\", \"{name}\", {value}]")
            }
            Self::Array { salt, value, .. } => {
                write!(f, "[\"{salt}\", {value}]")
            }
        }
    }
}

impl std::str::FromStr for Disclosure {
    type Err = SdjError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = base64_simd::URL_SAFE_NO_PAD.decode_to_vec(s.as_bytes())?;
        let json = serde_json::from_slice::<serde_json::Value>(&decoded)?;
        let array = json.as_array().ok_or(SdjError::InvalidDisclosure)?;
        match array.as_slice() {
            [salt, name, value] => {
                let salt = salt.as_str().ok_or(SdjError::InvalidDisclosure)?.parse()?;
                let name = name.as_str().ok_or(SdjError::InvalidDisclosure)?.to_string();

                Ok(Disclosure::Object {
                    salt,
                    name,
                    value: value.clone(),
                    hasher: core::marker::PhantomData,
                })
            }
            [salt, value] => {
                let salt = salt.as_str().ok_or(SdjError::InvalidDisclosure)?.parse()?;

                Ok(Disclosure::Array {
                    salt,
                    value: value.clone(),
                    hasher: core::marker::PhantomData,
                })
            }
            _ => Err(SdjError::InvalidDisclosure),
        }
    }
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

        let disclosure = Disclosure::Array {
            salt: salt.parse::<Salt<16>>().unwrap(),
            value: serde_json::json!(value),
            hasher: core::marker::PhantomData::<sha2::Sha256>,
        };
        assert_eq!(
            disclosure.encode().unwrap(),
            "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0".to_string()
        );
    }

    /// See also: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.3
    #[test]
    fn should_pass_rfc_example_for_hash() {
        let (salt, value) = ("lklxF5jMYlGTPUovMNIvCA", "FR");

        let disclosure = Disclosure::Array {
            salt: salt.parse::<Salt<16>>().unwrap(),
            value: serde_json::json!(value),
            hasher: core::marker::PhantomData::<sha2::Sha256>,
        };
        let hash: String = disclosure.hash().unwrap().into();
        assert_eq!(hash, "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs".to_string());
    }
}
