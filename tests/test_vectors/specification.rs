#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Specification {
    pub user_claims: serde_yaml::Value,
    pub holder_disclosed_claims: serde_yaml::Value,
    pub expect_verified_user_claims: serde_yaml::Value,
}

impl Specification {
    const FILENAME: &'static str = "specification.yml";
}

impl From<&str> for Specification {
    fn from(base_path: &str) -> Self {
        let specification = std::fs::read_to_string(&format!("{base_path}/{}", Self::FILENAME)).unwrap();
        serde_yaml::from_str(&specification).unwrap()
    }
}
