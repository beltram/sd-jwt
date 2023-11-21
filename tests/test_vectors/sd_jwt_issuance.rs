use selective_disclosure_jwt::prelude::SDJwt;
use std::error::Error;

/// Test struct to map the `sd_jwt_issuance.json` file in e2e tests and compare it
/// to a SD-JWT without making a mess there
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SdJwtIssuance {
    pub disclosures: Vec<String>,
    pub payload: String,
    pub protected: String,
    pub signature: String,
}

impl SdJwtIssuance {
    const FILENAME: &'static str = "sd_jwt_issuance.json";

    pub fn verify(&self, base_path: &str, sd_jwt: &SDJwt) {
        // === Disclosures ===
        println!("{:#?}", self.disclosures);
        for actual in sd_jwt.disclosures.iter() {
            let actual = actual.hash().unwrap().to_string();
            assert!(
                self.disclosures.contains(&actual),
                "Could not find {actual} in {}",
                Self::path(base_path)
            );
        }
    }

    fn path(base_path: &str) -> String {
        format!("{base_path}/{}", Self::FILENAME)
    }
}

impl From<&str> for SdJwtIssuance {
    fn from(base_path: &str) -> Self {
        let sd_jwt_issuance = std::fs::read_to_string(&Self::path(base_path)).unwrap();
        let sd_jwt_issuance = sd_jwt_issuance.replace("\\\"", "\"");
        let sd_jwt_issuance = sd_jwt_issuance.trim_start_matches('"').trim_end_matches('"');
        serde_json::from_str::<Self>(&sd_jwt_issuance).unwrap()
    }
}
