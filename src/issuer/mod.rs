use crate::{
    core::jws::Jws,
    crypto::CryptoBackend,
    error::SdjResult,
    issuer::{options::IssuerOptions, payload::JwtPayload},
    prelude::SDJwt,
};
use input::InputClaimSet;
use jwt_simple::prelude::Ed25519KeyPair;

mod decisions;
mod disclosure;
pub mod input;
mod jws;
pub mod options;
mod payload;
mod sd_jwt;

pub struct Issuer {
    pub(crate) backend: CryptoBackend,
    pub(crate) signature_key: String,
}

impl Issuer {
    pub fn try_new() -> SdjResult<Self> {
        let backend = CryptoBackend::new();
        // TODO: obviously move this to constructor
        let signature_key = Ed25519KeyPair::generate().to_pem();
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
}

// TODO: cleanup at some point
impl Issuer {
    pub fn get_signature_key(&self) -> String {
        self.signature_key.clone()
    }
}

#[cfg(test)]
pub mod tests {}
