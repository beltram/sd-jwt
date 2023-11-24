use crate::test_vectors::runner::{TestRunner, Tests};
use selective_disclosure_jwt::prelude::StdClaims;

pub mod runner;
pub mod sd_jwt_issuance;
pub mod specification;

#[test]
fn sample() {
    TestRunner::run(Tests::Sample, StdClaims { ..Default::default() }).unwrap();
}
