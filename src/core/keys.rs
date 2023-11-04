use jwt_simple::prelude::{ES256KeyPair, ES384KeyPair, Ed25519KeyPair};

use crate::prelude::SdjError;

#[derive(derive_more::AsRef, derive_more::Deref)]
pub struct JwsSignatureKeyPair<KP>(KP);

impl TryFrom<&str> for JwsSignatureKeyPair<Ed25519KeyPair> {
    type Error = SdjError;

    fn try_from(pem: &str) -> Result<Self, Self::Error> {
        Ok(Self(Ed25519KeyPair::from_pem(pem)?))
    }
}

impl TryFrom<Ed25519KeyPair> for JwsSignatureKeyPair<Ed25519KeyPair> {
    type Error = SdjError;

    fn try_from(kp: Ed25519KeyPair) -> Result<Self, Self::Error> {
        Ok(Self(kp))
    }
}

impl TryFrom<&str> for JwsSignatureKeyPair<ES256KeyPair> {
    type Error = SdjError;

    fn try_from(pem: &str) -> Result<Self, Self::Error> {
        Ok(Self(ES256KeyPair::from_pem(pem)?))
    }
}

impl TryFrom<&str> for JwsSignatureKeyPair<ES384KeyPair> {
    type Error = SdjError;

    fn try_from(pem: &str) -> Result<Self, Self::Error> {
        Ok(Self(ES384KeyPair::from_pem(pem)?))
    }
}
