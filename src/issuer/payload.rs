use crate::core::disclosure::Disclosure;
use crate::crypto::CryptoBackend;
use crate::error::{SdjError, SdjResult};
use crate::issuer::options::IssuerOptions;
use crate::prelude::InputClaimSet;

#[derive(serde::Serialize, serde::Deserialize, derive_more::Deref)]
pub(super) struct JwtPayload(pub(super) serde_json::Value);

impl JwtPayload {
    pub(super) fn try_new(
        backend: &mut CryptoBackend,
        mut input: InputClaimSet,
        options: &IssuerOptions,
    ) -> SdjResult<(JwtPayload, Vec<Disclosure>)> {
        let disclosures = input.try_select_disclosures(backend)?;

        let sd_alg = options.hash_alg.to_jwt_claim();

        let disclosures_hashes = disclosures
            .iter()
            .map(Disclosure::hash)
            .collect::<SdjResult<Vec<_>>>()?;

        let mut payload = serde_json::json!({
            "_sd": disclosures_hashes,
            "_sd_alg": sd_alg,
        });

        let disclosed = input.input.as_object_mut().ok_or(SdjError::ImplementationError)?;
        payload
            .as_object_mut()
            .ok_or(SdjError::ImplementationError)?
            .append(disclosed);

        Ok((JwtPayload(payload), disclosures))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::issuer::input::InputClaimSet;
    use serde_json::json;

    /// See also https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.5
    #[test]
    fn should_pass_rfc_example() {
        let input = json!({
            "sub": "user_42",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "given_name": "John",
            "family_name": "Doe",
            "email": "johndoe@example.com",
            "phone_number": "+1-202-555-0101",
            "phone_number_verified": true,
            "address": {
              "street_address": "123 Main St",
              "locality": "Anytown",
              "region": "Anystate",
              "country": "US"
            },
            "birthdate": "1940-01-01",
            "updated_at": 1570000000,
            "nationalities": [
              "US",
              "DE"
            ]
        });

        let decisions = &[
            "/given_name",
            "/family_name",
            "/email",
            "/phone_number",
            "/phone_number_verified",
            "/address",
            "/birthdate",
            "/updated_at",
            "/nationalities/1",
            "/nationalities/0",
        ];
        let input_claims = InputClaimSet::try_new(input, decisions).unwrap();

        let options = IssuerOptions::default();
        let (payload, _) = JwtPayload::try_new(&mut CryptoBackend::new(), input_claims, &options).unwrap();

        // hash
        assert_eq!(payload.get("_sd_alg"), Some(&json!("sha-256")));

        // visible claims
        assert_eq!(payload.get("iss"), Some(&json!("https://example.com/issuer")));
        assert_eq!(payload.get("iat"), Some(&json!(1683000000)));
        assert_eq!(payload.get("exp"), Some(&json!(1883000000)));
        assert_eq!(payload.get("sub"), Some(&json!("user_42")));

        // assert nationalities inner items
        let nationalities = payload.get("nationalities").unwrap().as_array().unwrap();
        assert_eq!(nationalities.len(), 2);
        for nationality in nationalities {
            let nationality = nationality.as_object().unwrap();
            assert_eq!(nationality.len(), 1);
            assert!(nationality.contains_key("..."));
            assert!(!nationality.get("...").unwrap().as_str().unwrap().is_empty());
        }

        // verify disclosures hashes
        let disclosures = payload.get("_sd").unwrap().as_array().unwrap();
        assert_eq!(disclosures.len(), 8);
        for d in disclosures {
            assert!(!d.as_str().unwrap().is_empty());
        }
    }
}
