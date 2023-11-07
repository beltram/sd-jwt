use crate::core::disclosure::Disclosure;
use crate::core::json_pointer::path::JsonPointerPath;
use crate::core::json_pointer::JsonPointer;
use crate::error::{SdjError, SdjResult};
use crate::prelude::{JwsAlgorithm, SDJwt};
use serde_json::json;

pub struct Holder;

impl Holder {
    // TODO: highly inefficient implementation ! To improve
    pub fn select(
        sd_jwt: &str,
        paths: &[&'static str],
        alg: JwsAlgorithm,
        issuer_verifying_key: &str,
    ) -> SdjResult<SDJwt> {
        let mut sd_jwt = sd_jwt.parse::<SDJwt>()?;
        let paths = paths
            .iter()
            .map(|&p| JsonPointerPath::try_from(p))
            .collect::<SdjResult<Vec<_>>>()?;

        let payload = sd_jwt.jws.try_read_payload(alg, issuer_verifying_key)?;
        let payload = json!(payload);

        let mut selected_disclosures = vec![];

        for path in paths {
            let disclosure = if let Some(key) = path.object_key() {
                let disclosure_hashes = payload
                    .try_find_disclosure(&path)?
                    .as_array()
                    .ok_or(SdjError::ImplementationError)?
                    .iter()
                    .map(|v| v.as_str().ok_or(SdjError::InvalidDisclosure))
                    .collect::<SdjResult<Vec<_>>>()?;

                let disclosure = sd_jwt
                    .disclosures
                    .iter()
                    .find(|d| matches!(d, Disclosure::Object { name, .. } if name == key))
                    .ok_or(SdjError::UnknownDisclosure)?;

                let hash = disclosure.hash()?;
                let is_included = disclosure_hashes.contains(&hash.as_str());

                if is_included {
                    disclosure
                } else {
                    return Err(SdjError::UnknownDisclosure);
                }
            } else {
                let disclosure_hash = payload
                    .try_find_disclosure(&path)?
                    .as_str()
                    .ok_or(SdjError::ImplementationError)?;

                sd_jwt
                    .disclosures
                    .iter()
                    .find(|d| match d {
                        Disclosure::Array { .. } => d.hash().unwrap().as_str() == disclosure_hash,
                        _ => false,
                    })
                    .ok_or(SdjError::UnknownDisclosure)?
            };
            selected_disclosures.push(disclosure.clone());
        }

        sd_jwt.disclosures.retain(|d| selected_disclosures.contains(d));

        Ok(sd_jwt)
    }
}
