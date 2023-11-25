use crate::test_vectors::runner::{TestRunner, Tests};
use selective_disclosure_jwt::prelude::StdClaims;

pub mod runner;
pub mod sd_jwt_issuance;
pub mod specification;

const ISSUER: &'static str = "https://example.com/issuer";
const IAT: u64 = 1683000000;
const EXPIRY: u64 = 1883000000;

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
