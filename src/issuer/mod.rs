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
mod json_pointer;
mod jws;
pub mod options;
mod payload;
mod sdjwt;

pub struct Issuer {
    pub(crate) backend: CryptoBackend,
}

impl Issuer {
    pub fn try_new() -> SdjResult<Self> {
        let backend = CryptoBackend::new();
        Ok(Self { backend })
    }

    pub fn try_generate_sdjwt(
        &mut self,
        input: serde_json::Value,
        decisions: &'static [&'static str],
        options: IssuerOptions,
    ) -> SdjResult<SDJwt> {
        let input = InputClaimSet::try_new(input, decisions)?;
        let (payload, disclosures) = JwtPayload::try_new(&mut self.backend, input, &options)?;
        let jws = Jws::try_new(payload)?;
        Ok(SDJwt {
            jws,
            disclosures,
            key_binding: None,
        })
    }
}

impl crate::ThirdParty for Issuer {}

#[cfg(test)]
pub mod tests {}
