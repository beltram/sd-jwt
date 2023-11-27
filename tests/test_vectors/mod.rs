use crate::test_vectors::runner::{TestRunner, Tests};
use jwt_simple::prelude::Jwk;
use selective_disclosure_jwt::prelude::StdClaims;
use serde_json::json;

pub mod runner;
pub mod sd_jwt_issuance;
pub mod specification;

const ISSUER: &'static str = "https://example.com/issuer";
const IAT: u64 = 1683000000;
const EXPIRY: u64 = 1883000000;
const HOLDER_KEY: &'static str = "-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemdnGOJZZtkxAYdVYpVDiFtIiKuxV+55wITq3iNP0XYdlA==-----END PUBLIC KEY-----";

#[test]
fn sample() {
    let std_claims = StdClaims {
        issued_at: Some(IAT),
        expiry: Some(EXPIRY),
        not_before: None,
        issuer: Some(ISSUER.to_string()),
        ..Default::default()
    };
    TestRunner::run(Tests::Sample, std_claims).unwrap();
}
