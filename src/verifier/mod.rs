use crate::error::SdjResult;
use crate::prelude::{JwsAlgorithm, SDJwt};
use serde_json::{json, Value};

pub struct Verifier;

impl Verifier {
    pub fn verify(sd_jwt: &str, alg: JwsAlgorithm, issuer_verifying_key: &str) -> SdjResult<()> {
        let sd_jwt = sd_jwt.parse::<SDJwt>()?;
        Ok(())
    }

    pub fn try_read_payload(sd_jwt: &str, alg: JwsAlgorithm, issuer_verifying_key: &str) -> SdjResult<Value> {
        Self::verify(sd_jwt, alg, issuer_verifying_key)?;

        let mut sd_jwt = sd_jwt.parse::<SDJwt>()?;
        let payload = sd_jwt.jws.try_read_payload(alg, issuer_verifying_key)?;

        Ok(json!({}))
    }
}
