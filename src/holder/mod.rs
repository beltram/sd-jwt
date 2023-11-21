use crate::core::disclosure::Disclosure;
use crate::core::json_pointer::path::JsonPointerPath;
use crate::core::json_pointer::JsonPointer;
use crate::error::{SdjError, SdjResult};
use crate::issuer::UserInput;
use crate::prelude::{JwsAlgorithm, SDJwt};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

pub struct Holder;

impl Holder {
    // TODO: highly inefficient implementation ! To improve
    pub fn try_select(
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
                    .filter(|d| matches!(d, Disclosure::Object { name, .. } if name == key))
                    .find(|d| disclosure_hashes.contains(&d.hash().unwrap().as_str()))
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

    // TODO: highly inefficient implementation ! To improve
    pub fn try_select_yaml(
        sd_jwt: &str,
        user_input: &YamlValue,
        alg: JwsAlgorithm,
        issuer_verifying_key: &str,
    ) -> SdjResult<SDJwt> {
        let mut sd_jwt = sd_jwt.parse::<SDJwt>()?;
        let payload = sd_jwt.jws.try_read_payload(alg, issuer_verifying_key)?;
        println!("== {}", serde_json::to_string_pretty(&payload).unwrap());
        let selected_disclosures = Self::pick_disclosures_yaml(user_input, &payload, &sd_jwt.disclosures)?;
        sd_jwt.disclosures.retain(|d| selected_disclosures.contains(d));
        Ok(sd_jwt)
    }

    pub fn pick_disclosures_yaml(
        user_input: &YamlValue,
        json_payload: &JsonValue,
        disclosures: &Vec<Disclosure>,
    ) -> SdjResult<Vec<Disclosure>> {
        let mut selected_disclosures = vec![];
        match user_input {
            YamlValue::Mapping(yaml_obj) => {
                let sd = json_payload.get("_sd").ok_or(SdjError::InvalidHolderSelection)?;
                let sd = sd.as_array().ok_or(SdjError::InvalidDisclosure)?;
                let sd = sd
                    .into_iter()
                    .map(|d| d.as_str().ok_or(SdjError::InvalidDisclosure))
                    .collect::<SdjResult<Vec<_>>>()?;

                for (yaml_key, yaml_value) in yaml_obj.iter() {
                    match (yaml_key, yaml_value) {
                        (YamlValue::String(key), YamlValue::Bool(take)) if *take == true => {
                            println!("> {yaml_key:?}: {yaml_value:?}");
                            let disclosure = disclosures
                                .iter()
                                .filter(|d| matches!(d, Disclosure::Object {name, ..} if name == key))
                                .find(|d| sd.contains(&d.hash().unwrap().as_str()))
                                .ok_or(SdjError::InvalidHolderSelection)?;
                            selected_disclosures.push(disclosure.clone());
                        }
                        _ => {}
                    }
                }
            }
            YamlValue::Sequence(array) => {}
            _ => {}
        }

        Ok(selected_disclosures)
    }
}
