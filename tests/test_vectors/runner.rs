use jwt_simple::prelude::*;
use std::error::Error;

use strum::Display;

use selective_disclosure_jwt::prelude::{Issuer, IssuerOptions, JwsAlgorithm};

use crate::test_vectors::{sd_jwt_issuance::SdJwtIssuance, specification::Specification};

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
    const JWS_ALG: JwsAlgorithm = JwsAlgorithm::P256;
    const BASE: &'static str = "tests/test_vectors/testcases";

    pub fn run(test: Tests) -> Result<(), Box<dyn Error>> {
        println!("\n=== Running {test} ===\n");

        let base_path = format!("{}/{test}", Self::BASE);

        let specification = Specification::from(base_path.as_str());

        let signature_key = match Self::JWS_ALG {
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::generate().to_pem(),
            JwsAlgorithm::P256 => ES256KeyPair::generate().to_pem().unwrap(),
            JwsAlgorithm::P384 => ES384KeyPair::generate().to_pem().unwrap(),
        };

        // === Issuer ===
        let mut issuer = Issuer::try_new(signature_key)?;
        let issuer_options = IssuerOptions {
            sign_alg: Self::JWS_ALG,
            ..Default::default()
        };
        let sd_jwt = issuer.try_generate_sd_jwt_yaml(&specification.user_claims.into(), issuer_options)?;

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
