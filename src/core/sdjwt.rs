use crate::core::disclosure::Disclosure;
use crate::core::jws::Jws;

/// A Selective Disclosure JWT composed of
/// * the Issuer-signed JWT
/// * the Disclosures
/// * optionally a Key Binding JWT
///
/// See also: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.11
#[derive()]
pub struct SDJwt {
    pub(crate) jws: Jws,
    pub(crate) disclosures: Vec<Disclosure>,
    pub(crate) key_binding: Option<String>,
}
