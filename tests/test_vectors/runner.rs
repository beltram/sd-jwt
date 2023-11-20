use selective_disclosure_jwt::prelude::{Issuer, IssuerOptions};
use std::error::Error;
use std::path::PathBuf;
use strum::Display;

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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Specification {
    user_claims: serde_yaml::Value,
    holder_disclosed_claims: serde_yaml::Value,
    expect_verified_user_claims: serde_yaml::Value,
}

pub struct TestRunner;

impl TestRunner {
    pub fn run(test: Tests) -> Result<(), Box<dyn Error>> {
        let path = format!("tests/test_vectors/testcases/{test}/specification.yml");
        let file = std::fs::File::open(&PathBuf::from(path)).unwrap();

        let Specification {
            user_claims,
            holder_disclosed_claims,
            expect_verified_user_claims,
        } = serde_yaml::from_reader::<_, Specification>(&file).unwrap();

        let mut issuer = Issuer::try_new()?;

        let sd_jwt = issuer.try_generate_sd_jwt_yaml(&user_claims.into(), IssuerOptions::default())?;

        println!("{:?}", sd_jwt.jws.to_string());

        Ok(())
    }
}
