use crate::issuer::select::SelectDisclosures;
use crate::{
    core::jws::Jws,
    crypto::CryptoBackend,
    error::SdjResult,
    issuer::{options::IssuerOptions, payload::JwtPayload},
    prelude::SDJwt,
};
use input::InputClaimSet;

mod decisions;
mod disclosure;
pub mod input;
mod jws;
pub mod options;
mod payload;
mod sd_jwt;
mod select;

#[derive(Debug, Clone, derive_more::AsRef, derive_more::Deref, derive_more::From, derive_more::Into)]
pub struct UserInput(serde_yaml::Value);

pub struct Issuer {
    pub(crate) backend: CryptoBackend,
    pub(crate) signature_key: String,
}

impl Issuer {
    // TODO: have a generic wrapper over keys, this sucks
    pub fn try_new(signature_key: String) -> SdjResult<Self> {
        let backend = CryptoBackend::new();
        Ok(Self { backend, signature_key })
    }

    pub fn try_generate_sd_jwt(
        &mut self,
        input: &serde_json::Value,
        decisions: &'static [&'static str],
        options: IssuerOptions,
    ) -> SdjResult<SDJwt> {
        let input = InputClaimSet::try_new(input, decisions)?;
        let (payload, disclosures) = JwtPayload::try_new(&mut self.backend, input, &options)?;
        let jws = Jws::try_new(payload, options.sign_alg, &self.signature_key)?;
        Ok(SDJwt {
            jws,
            disclosures,
            key_binding: None,
        })
    }

    pub fn try_generate_sd_jwt_yaml(&mut self, input: &UserInput, options: IssuerOptions) -> SdjResult<SDJwt> {
        let (payload, disclosures) = input.clone().0.try_select_items(&mut self.backend, &options)?;
        let jws = Jws::try_new(JwtPayload(payload), options.sign_alg, &self.signature_key)?;
        Ok(SDJwt {
            jws,
            disclosures,
            key_binding: None,
        })
    }
}

// TODO: cleanup at some point
impl Issuer {
    pub fn get_signature_key(&self) -> String {
        self.signature_key.clone()
    }
}

#[cfg(test)]
pub mod tests {}

#[test]
fn toto() {
    let rust = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImV4YW1wbGUrc2Qtand0In0";
    let python = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0";

    println!("rust  : {}", decode(rust));
    println!("python: {}", decode(python));

    fn decode(s: &str) -> String {
        use base64::Engine;

        let d = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(s.as_bytes()).unwrap();
        std::str::from_utf8(&d).unwrap().to_string()
    }
}
