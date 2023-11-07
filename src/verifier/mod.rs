use serde_json::{json, Value};
use crate::error::SdjResult;
use crate::prelude::SDJwt;

pub struct Verifier;

impl Verifier {
    pub fn verify(sd_jwt: &str, issuer_verifying_key: &str) -> SdjResult<()> {
        let mut sd_jwt = sd_jwt.parse::<SDJwt>()?;
        Ok(())
    }
    
    pub fn try_read_payload(sd_jwt: &str, issuer_verifying_key: &str) -> SdjResult<Value> {
        Ok(json!({}))
    }
}
