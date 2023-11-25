use crate::issuer::payload::JwtPayload;
use fluvio_wasm_timer::SystemTime;
use jwt_simple::prelude::*;
use std::collections::HashSet;

/// JWT standard registered claims.
/// Those will by default be always visible. If you want them to be disclosable just set them to
/// `None` in here and supply them in the input.
/// See also: https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims#registered-claims
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StdClaims {
    /// Issuer - This can be set to anything application-specific
    #[serde(rename = "iss", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Time the claims were created at
    #[serde(rename = "iat", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    /// Time the claims expire at
    #[serde(rename = "exp", default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
    /// Time the claims will be invalid until
    #[serde(rename = "nbf", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
    /// Subject - This can be set to anything application-specific
    #[serde(rename = "sub", default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Audience
    #[serde(rename = "aud", default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<HashSet<String>>,
    /// JWT identifier
    ///
    /// That property was originally designed to avoid replay attacks, but
    /// keeping all previously sent JWT token IDs is unrealistic.
    ///
    /// Replay attacks are better addressed by keeping only the timestamp of the
    /// last valid token for a user, and rejecting anything older in future
    /// tokens.
    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl StdClaims {
    /// To prevent clock skews it is recommended to set 'iat' & 'nbf' slightly in the past
    const DEFAULT_LEEWAY: core::time::Duration = core::time::Duration::from_secs(60 * 60);

    /// Default (and sane) expiry for a token
    const DEFAULT_EXPIRY: core::time::Duration = core::time::Duration::from_secs(60 * 60 * 24);

    pub fn now_or_epoch() -> u64 {
        let now = SystemTime::now() - Self::DEFAULT_LEEWAY;
        now.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| core::time::Duration::from_secs(0))
            .as_secs()
    }
}

impl Default for StdClaims {
    fn default() -> Self {
        let now = Self::now_or_epoch();
        Self {
            issued_at: Some(now),
            not_before: Some(now),
            expiry: Some(now + Self::DEFAULT_EXPIRY.as_secs()),
            subject: None,
            audience: None,
            issuer: None,
            jti: None,
        }
    }
}
