#[cfg(feature = "issuer")]
use crate::core::disclosure::Disclosure;
use crate::error::{SdjError, SdjResult};
use serde_json::Value;

pub(crate) mod path;

/// Home baked JSON Pointer implementation that also drops the selected value
///
/// For more information read [RFC6901](https://tools.ietf.org/html/rfc6901)
pub(crate) trait JsonPointer {
    /// Finds the value by JSON Pointer then removes the key from the JSON Value
    /// and returns the key name and value in order to build a [crate::core::disclosure::Disclosure]
    // TODO: have this return a Result
    #[cfg(feature = "issuer")]
    fn try_find_drop(
        &mut self,
        backend: &mut crate::crypto::CryptoBackend,
        path: &path::JsonPointerPath,
    ) -> SdjResult<Disclosure>;

    fn try_find_disclosure(&self, path: &path::JsonPointerPath) -> SdjResult<&Value>;
}

impl JsonPointer for Value {
    #[cfg(feature = "issuer")]
    fn try_find_drop(
        &mut self,
        backend: &mut crate::crypto::CryptoBackend,
        path: &path::JsonPointerPath,
    ) -> SdjResult<Disclosure> {
        use serde_json::json;
        let tokens = path
            .split('/')
            .skip(1)
            .map(|x| x.replace("~1", "/").replace("~0", "~"))
            .collect::<Vec<_>>();
        let tokens_len = tokens.len();

        let mut disclosure = None;

        // TODO: better error handling
        tokens
            .into_iter()
            .enumerate()
            .try_fold(
                (String::new(), Some(self)),
                |(_, previous), (index, token)| match previous {
                    Some(Value::Object(map)) => {
                        let is_last_token = index == tokens_len - 1;
                        if is_last_token {
                            let value = map.remove(&token)?;
                            let _disclosure = Disclosure::try_new_object(backend, token.clone(), value).ok()?;
                            let hash = _disclosure.hash().ok()?;
                            disclosure = Some(_disclosure);

                            map.entry("_sd")
                                .and_modify(|e| e.as_array_mut().unwrap().push(json!(hash)))
                                .or_insert_with(|| json!([hash]));

                            None
                        } else {
                            let next = map.get_mut(&token);
                            next.map(|value| (token, Some(value)))
                        }
                    }
                    Some(Value::Array(list)) => {
                        use std::str::FromStr as _;
                        let item_index = usize::from_str(&token).ok()?;
                        let item = list.get_mut(item_index)?;

                        let _disclosure = Disclosure::try_new_array(backend, item.clone()).ok()?;
                        let hash = _disclosure.hash().ok()?;
                        disclosure = Some(_disclosure);
                        *item = json!({"...": hash});

                        None
                    }
                    _ => None,
                },
            );

        disclosure.ok_or_else(|| SdjError::InvalidJsonPointerPath(path.to_string()))
    }

    fn try_find_disclosure(&self, path: &path::JsonPointerPath) -> SdjResult<&Value> {
        if path.is_key() {
            let mut path = path
                .parent()
                .ok_or(SdjError::InvalidJsonPointerPath(path.to_string()))?;
            path.append("_sd");
            self.pointer(&path)
                .ok_or(SdjError::InvalidJsonPointerPath(path.to_string()))
        } else {
            let value = self
                .pointer(path)
                .ok_or(SdjError::InvalidJsonPointerPath(path.to_string()))?;
            let obj = value.as_object().ok_or(SdjError::InvalidJwt)?;
            obj.get("...").ok_or(SdjError::InvalidJwt)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::CryptoBackend;
    use serde_json::json;

    #[test]
    fn should_find_and_take_primitive() {
        let mut backend = CryptoBackend::new();
        let mut input = json!({
            "string": "s",
            "int": 42,
            "float": 4.13,
            "bool": false,
            "obj": {
                "a": 1,
                "b": 2
            },
            "array": [0, 1, 2]
        });

        // string
        let path = "/string".try_into().unwrap();
        let Ok(Disclosure::Object { name, value, .. }) = input.try_find_drop(&mut backend, &path) else {
            unimplemented!()
        };
        assert_eq!(name, "string");
        assert_eq!(value, "s");
        assert!(input.get("string").is_none());
        assert_eq!(input.get("_sd").unwrap().as_array().unwrap().len(), 1);

        // int
        let path = "/int".try_into().unwrap();
        let Ok(Disclosure::Object { name, value, .. }) = input.try_find_drop(&mut backend, &path) else {
            unimplemented!()
        };
        assert_eq!(name, "int");
        assert_eq!(value, 42);
        assert!(input.get("int").is_none());
        assert_eq!(input.get("_sd").unwrap().as_array().unwrap().len(), 2);

        // float
        let path = "/float".try_into().unwrap();
        let Ok(Disclosure::Object { name, value, .. }) = input.try_find_drop(&mut backend, &path) else {
            unimplemented!()
        };
        assert_eq!(name, "float");
        assert_eq!(value, 4.13);
        assert!(input.get("float").is_none());
        assert_eq!(input.get("_sd").unwrap().as_array().unwrap().len(), 3);

        // bool
        let path = "/bool".try_into().unwrap();
        let Ok(Disclosure::Object { name, value, .. }) = input.try_find_drop(&mut backend, &path) else {
            unimplemented!()
        };
        assert_eq!(name, "bool");
        assert_eq!(value, false);
        assert!(input.get("bool").is_none());
        assert_eq!(input.get("_sd").unwrap().as_array().unwrap().len(), 4);

        // object
        let path = "/obj".try_into().unwrap();
        let Ok(Disclosure::Object { name, value, .. }) = input.try_find_drop(&mut backend, &path) else {
            unimplemented!()
        };
        assert_eq!(name, "obj");
        assert_eq!(value, json!({"a": 1, "b": 2}));
        assert!(input.get("obj").is_none());
        assert_eq!(input.get("_sd").unwrap().as_array().unwrap().len(), 5);

        // array
        let path = "/array".try_into().unwrap();
        let Ok(Disclosure::Object { name, value, .. }) = input.try_find_drop(&mut backend, &path) else {
            unimplemented!()
        };
        assert_eq!(name, "array");
        assert_eq!(value, json!([0, 1, 2]));
        assert!(input.get("array").is_none());
        assert_eq!(input.get("_sd").unwrap().as_array().unwrap().len(), 6);
    }

    #[test]
    fn should_find_and_replace_array_item() {
        let mut backend = CryptoBackend::new();

        let mut input = json!({"array": [0, 1, 2]});

        let path = "/array/2".try_into().unwrap();
        let Ok(Disclosure::Array { value, .. }) = input.try_find_drop(&mut backend, &path) else {
            unimplemented!()
        };
        assert_eq!(value, json!(2));

        let array = input.get("array").unwrap().as_array().unwrap();
        assert_eq!(array.get(0).unwrap(), &json!(0));
        assert_eq!(array.get(1).unwrap(), &json!(1));

        let item_as_disclosure = array.get(2).unwrap().as_object().unwrap();
        assert!(!item_as_disclosure.get("...").unwrap().as_str().unwrap().is_empty());
    }

    #[test]
    fn should_fail_when_not_found() {
        let mut backend = CryptoBackend::new();

        let mut input = json!({"a": 1});

        let path = "/b".try_into().unwrap();
        assert!(matches!(
                input.try_find_drop(&mut backend, &path).unwrap_err(),
                SdjError::InvalidJsonPointerPath(p) if p == "/b"
        ));
    }
}
