use std::ops::DerefMut;
use std::process::Termination;

use serde_json::{json, Value as JsonValue};
use serde_yaml::{Mapping, Value as YamlValue, Value};

use crate::core::disclosure::Disclosure;
use crate::crypto::CryptoBackend;
use crate::error::SdjResult;
use crate::prelude::IssuerOptions;

pub trait SelectDisclosures {
    fn try_select_items(
        self,
        backend: &mut CryptoBackend,
        options: &IssuerOptions,
    ) -> SdjResult<(JsonValue, Vec<Disclosure>)>;

    fn try_apply_disclosures(
        &mut self,
        backend: &mut CryptoBackend,
        options: &IssuerOptions,
    ) -> SdjResult<Vec<Disclosure>>;
}

impl SelectDisclosures for YamlValue {
    fn try_select_items(
        mut self,
        backend: &mut CryptoBackend,
        options: &IssuerOptions,
    ) -> SdjResult<(JsonValue, Vec<Disclosure>)> {
        let disclosures = self.try_apply_disclosures(backend, options)?;
        let json = serde_yaml::from_value::<JsonValue>(self)?;
        Ok((json, disclosures))
    }

    fn try_apply_disclosures(
        &mut self,
        backend: &mut CryptoBackend,
        options: &IssuerOptions,
    ) -> SdjResult<Vec<Disclosure>> {
        let mut disclosures = vec![];

        match self {
            Value::Mapping(obj) => {
                obj.retain(|k, mut v| {
                    match (k, v.deref_mut()) {
                        (YamlValue::Tagged(tagged), _) if tagged.tag == "!sd" => {
                            let name = tagged.value.as_str().unwrap();
                            let value = serde_yaml::from_value::<JsonValue>(v.clone()).unwrap();
                            let disclosure = Disclosure::try_new_object(backend, name.to_string(), value).unwrap();
                            disclosures.push(disclosure);
                            return false;
                        }
                        (_, YamlValue::Mapping(_) | YamlValue::Sequence(_)) => {
                            disclosures
                                .append(&mut v.try_apply_disclosures(backend, options).unwrap())
                                .report();
                        }
                        (_, _) => {}
                    }
                    true
                });
                if !disclosures.is_empty() {
                    let disclosure_hashes = disclosures
                        .iter()
                        .map(|d| d.hash().unwrap())
                        .map(|d| YamlValue::String(d.to_string()))
                        .collect::<Vec<_>>();
                    let disclosure_hashes = YamlValue::Sequence(disclosure_hashes);
                    obj.insert(YamlValue::String("_sd".to_string()), disclosure_hashes);
                }
            }
            Value::Sequence(array) => {
                for item in array.iter_mut() {
                    match &item {
                        Value::Tagged(tagged) if tagged.tag == "!sd" => {
                            let json_value = serde_yaml::from_value::<JsonValue>(tagged.value.clone()).unwrap();
                            let disclosure = Disclosure::try_new_array(backend, json_value).unwrap();
                            let hash = disclosure.hash().unwrap();

                            let (k, v) = (
                                YamlValue::String("...".to_string()),
                                YamlValue::String(hash.to_string()),
                            );

                            *item = YamlValue::Mapping(Mapping::from_iter([(k, v)]));
                            disclosures.push(disclosure);
                        }
                        Value::Mapping(_) | Value::Sequence(_) => {
                            disclosures.append(&mut item.try_apply_disclosures(backend, options).unwrap())
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        };

        Ok(disclosures)
    }
}
