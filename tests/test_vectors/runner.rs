use std::error::Error;

use strum::Display;

use selective_disclosure_jwt::prelude::{Issuer, IssuerOptions, JwsAlgorithm};

use crate::test_vectors::sd_jwt_issuance::SdJwtIssuance;
use crate::test_vectors::specification::Specification;

#[derive(Display, Debug)]
pub enum Tests {
    #[strum(serialize = "sample")]
    Sample,
    #[strum(serialize = "array_full_sd")]
    ArrayFullSd,
    #[strum(serialize = "array_data_types")]
    ArrayDataTypes,
}

pub const FILES: [&str; 9] = [
    "sd_jwt_issuance.txt",
    "sd_jwt_presentation.txt",
    "disclosures.md",
    "user_claims.json",
    "sd_jwt_payload.json",
    "sd_jwt_jws_part.txt",
    "kb_jwt_payload.json",
    "kb_jwt_serialized.txt",
    "verified_contents.json",
];

pub struct TestRunner;

impl TestRunner {
    const JWS_ALG: JwsAlgorithm = JwsAlgorithm::Ed25519;
    const BASE: &'static str = "tests/test_vectors/testcases";

    pub fn run(test: Tests) -> Result<(), Box<dyn Error>> {
        println!("\n=== Running {test} ===\n");

        let base_path = format!("{}/{test}", Self::BASE);

        let specification = Specification::from(base_path.as_str());

        // === Issuer ===
        let mut issuer = Issuer::try_new()?;
        let sd_jwt = issuer.try_generate_sd_jwt_yaml(&specification.user_claims.into(), IssuerOptions::default())?;

        SdJwtIssuance::from(base_path.as_str()).verify(base_path.as_str(), &sd_jwt);

        // === Holder ===

        /*let holder_sd_jwt = Holder::try_select_yaml(
            sd_jwt.try_serialize()?.as_str(),
            &specification.holder_disclosed_claims,
            JWS_ALG,
            &issuer.get_signature_key(),
        )?;*/

        Ok(())
    }
}
