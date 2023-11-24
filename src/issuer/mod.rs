use crate::issuer::select::SelectDisclosures;
use crate::issuer::std::StdClaims;
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
pub mod std;

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
        std_claims: StdClaims,
        options: IssuerOptions,
    ) -> SdjResult<SDJwt> {
        let input = InputClaimSet::try_new(input, decisions)?;
        let (payload, disclosures) = JwtPayload::try_new(&mut self.backend, input, &options)?;
        let jws = Jws::try_new(payload, std_claims, options.sign_alg, &self.signature_key)?;

        Ok(SDJwt {
            jws,
            disclosures,
            key_binding: None,
        })
    }

    // TODO: move all this mess into dedicated structs
    pub fn try_generate_sd_jwt_yaml(
        &mut self,
        input: &UserInput,
        std_claims: StdClaims,
        options: IssuerOptions,
    ) -> SdjResult<SDJwt> {
        let (payload, disclosures) = input.clone().0.try_select_items(&mut self.backend, &options)?;
        let payload = JwtPayload {
            values: payload,
            sd_alg: options.hash_alg.to_jwt_claim().to_string(),
        };
        let jws = Jws::try_new(payload, std_claims, options.sign_alg, &self.signature_key)?;
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
