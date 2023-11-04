use crate::error::SdjResult;
use crate::{
    core::{disclosure::Disclosure, jws::Jws},
    error::SdjError,
};
use std::str::FromStr;

/// A Selective Disclosure JWT composed of
/// * the Issuer-signed JWT
/// * the Disclosures
/// * optionally a Key Binding JWT
///
/// See also: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.11
#[derive(Debug)]
pub struct SDJwt {
    pub jws: Jws,
    pub disclosures: Vec<Disclosure>,
    pub key_binding: Option<String>,
}

impl SDJwt {
    pub const DELIMITER: &str = "~";
}

impl FromStr for SDJwt {
    type Err = SdjError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(Self::DELIMITER).collect::<Vec<_>>();
        if parts.len() < 3 {
            return Err(SdjError::InvalidSerializedSdJwt);
        }
        let size = parts.len();
        let jws = parts.remove(0).to_string().into();
        let disclosures = parts
            .drain(..size - 2)
            .map(|d| d.parse())
            .collect::<SdjResult<Vec<_>>>()?;
        let key_binding = parts.first().filter(|kb| !kb.is_empty()).map(|s| s.to_string());

        Ok(Self {
            jws,
            disclosures,
            key_binding,
        })
    }
}
