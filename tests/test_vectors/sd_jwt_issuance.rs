use selective_disclosure_jwt::prelude::SDJwt;

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
        // println!("{:#?}", self.disclosures);

        /*for d in &self.disclosures {
            let decoded = base64_simd::URL_SAFE_NO_PAD.decode_to_vec(&d).unwrap();
            let decoded = std::str::from_utf8(&decoded).unwrap();
            println!("python -> {decoded} => {d}");
        }*/

        for actual in sd_jwt.disclosures.iter() {
            let actual = actual.encode().unwrap();

            // let decoded = base64_simd::URL_SAFE_NO_PAD.decode_to_vec(&actual).unwrap();
            // let decoded = std::str::from_utf8(&decoded).unwrap();
            // println!("rust   => {decoded} => {actual}");
            assert!(
                self.disclosures.contains(&actual),
                "Could not find disclosure {actual} in {}",
                Self::path(base_path)
            );
        }
        // === Jws ===
        let (header, payload, signature) = sd_jwt.jws.to_parts();
        // assert_eq!(payload, self.payload, "SD-JWT payload did not match");
        // assert_eq!(signature, self.signature, "SD-JWT signature did not match");
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
