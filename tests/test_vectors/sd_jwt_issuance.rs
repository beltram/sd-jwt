use base64::Engine;
use selective_disclosure_jwt::prelude::SDJwt;
use serde_json::Value;

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
        for actual in sd_jwt.disclosures.iter() {
            let actual = actual.encode().unwrap();
            assert!(
                self.disclosures.contains(&actual),
                "Could not find disclosure {actual} in {}",
                Self::path(base_path)
            );
        }
        // === Jws ===
        let (header, payload, signature) = sd_jwt.jws.to_parts();
        assert_eq!(header, self.protected, "SD-JWT header did not match");

        decode_payload("rust  :", payload);
        decode_payload("python:", &self.payload);

        assert_eq!(payload, self.payload, "SD-JWT payload did not match");

        // assert_eq!(signature, self.signature, "SD-JWT signature did not match");
    }

    fn path(base_path: &str) -> String {
        format!("{base_path}/{}", Self::FILENAME)
    }
}

fn decode_payload(label: &str, payload: &str) {
    let payload = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(&payload).unwrap();
    let payload = serde_json::from_slice::<Value>(&payload).unwrap();
    let json = serde_json::to_string_pretty(&payload).unwrap();
    println!("{label} {payload}");
}

impl From<&str> for SdJwtIssuance {
    fn from(base_path: &str) -> Self {
        let sd_jwt_issuance = std::fs::read_to_string(&Self::path(base_path)).unwrap();
        let sd_jwt_issuance = sd_jwt_issuance.replace("\\\"", "\"");
        let sd_jwt_issuance = sd_jwt_issuance.trim_start_matches('"').trim_end_matches('"');
        serde_json::from_str::<Self>(&sd_jwt_issuance).unwrap()
    }
}
