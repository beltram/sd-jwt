use std::error::Error;
use std::path::PathBuf;
use strum::Display;

#[derive(Display, Debug)]
pub enum Tests {
    #[strum(serialize = "array_full_sd")]
    ArrayFullSd,
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
        // let file = std::fs::read(path)?;
        let path = PathBuf::from(path);
        let value = yaml_include::Transformer::new(path.clone(), false).unwrap().parse();

        println!("{:#?}", value);

        serde_yaml::from_reader::<_, Specification>(&std::fs::File::open(&path).unwrap()).unwrap();

        Ok(())
    }
}
