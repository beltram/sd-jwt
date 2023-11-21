use crate::test_vectors::runner::{TestRunner, Tests};

pub mod runner;
pub mod sd_jwt_issuance;
pub mod specification;

#[test]
fn sample() {
    TestRunner::run(Tests::Sample).unwrap();
    // TestRunner::run(Tests::ArrayDataTypes).unwrap();
}
