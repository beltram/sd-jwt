use crate::test_vectors::runner::{TestRunner, Tests};

pub mod runner;

#[test]
fn sample() {
    TestRunner::run(Tests::Sample).unwrap();
    // TestRunner::run(Tests::ArrayDataTypes).unwrap();
}
