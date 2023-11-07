use crate::test_vectors::runner::{TestRunner, Tests};

pub mod runner;

#[test]
fn array_full_sd() {
    TestRunner::run(Tests::ArrayFullSd).unwrap();
}
