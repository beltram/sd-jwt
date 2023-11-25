use crate::test_vectors::runner::{TestRunner, Tests};
use selective_disclosure_jwt::prelude::StdClaims;

pub mod runner;
pub mod sd_jwt_issuance;
pub mod specification;

const ISSUER: &'static str = "https://example.com/issuer";

#[test]
fn sample() {
    let now = StdClaims::now_or_epoch();
    let std_claims = StdClaims {
        issued_at: Some(now),
        not_before: Some(now),
        expiry: Some(now),
        issuer: Some(ISSUER.to_string()),
        ..Default::default()
    };
    TestRunner::run(Tests::Sample, std_claims).unwrap();
}
