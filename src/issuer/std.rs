use crate::issuer::payload::JwtPayload;
use fluvio_wasm_timer::SystemTime;
use jwt_simple::prelude::*;
use std::collections::HashSet;

/// JWT standard registered claims.
/// Those will by default be always visible. If you want them to be disclosable just set them to
/// `None` in here and supply them in the input.
/// See also: https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims#registered-claims
#[derive(Debug, Clone)]
pub struct StdClaims {
    /// Issuer URI
    pub issuer: Option<String>,
    /// Issuance timestamp
    pub issued_at: Option<u64>,
    /// Not valid before timestamp
    pub not_before: Option<u64>,
    /// Expiry timestamp
    pub expiry: Option<u64>,
    /// principal of the subject
    pub subject: Option<String>,
    /// intended receiver
    pub audience: Option<HashSet<String>>,
    /// Unique identifier
    pub jti: Option<String>,
}

impl StdClaims {
    /// To prevent clock skews it is recommended to set 'iat' & 'nbf' slightly in the past
    const DEFAULT_LEEWAY: core::time::Duration = core::time::Duration::from_secs(60 * 60);

    /// Default (and sane) expiry for a token
    const DEFAULT_EXPIRY: core::time::Duration = core::time::Duration::from_secs(60 * 60 * 24);

    pub fn to_inner_claims(self, payload: JwtPayload) -> JWTClaims<JwtPayload> {
        JWTClaims {
            issuer: self.issuer,
            issued_at: self.issued_at.map(UnixTimeStamp::from_secs),
            invalid_before: self.not_before.map(UnixTimeStamp::from_secs),
            expires_at: self.expiry.map(UnixTimeStamp::from_secs),
            subject: self.subject,
            audiences: self.audience.map(Audiences::AsSet),
            jwt_id: self.jti,
            nonce: None,
            custom: payload,
        }
    }

    fn now_or_epoch() -> u64 {
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
