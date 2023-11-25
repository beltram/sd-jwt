use serde_json::json;

use crate::prelude::StdClaims;
use crate::{
    core::disclosure::Disclosure, crypto::CryptoBackend, error::SdjResult, issuer::options::IssuerOptions,
    prelude::InputClaimSet,
};

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct JwtPayload {
    #[serde(flatten)]
    pub(super) values: serde_json::Value,
    #[serde(flatten)]
    pub(super) std_claims: StdClaims,
    #[serde(rename = "_sd_alg")]
    pub sd_alg: String,
}

impl JwtPayload {
    pub(super) fn try_new(
        backend: &mut CryptoBackend,
        mut input: InputClaimSet,
        std_claims: StdClaims,
        options: &IssuerOptions,
    ) -> SdjResult<(JwtPayload, Vec<Disclosure>)> {
        let disclosures = input.try_select_disclosures(backend)?;
        let payload = Self {
            values: input.input,
            std_claims,
            sd_alg: options.hash_alg.to_jwt_claim().to_string(),
        };
        Ok((payload, disclosures))
    }
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;

    use crate::issuer::input::InputClaimSet;

    use super::*;

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
        let input_claims = InputClaimSet::try_new(&input, decisions).unwrap();

        let options = IssuerOptions::default();
        let std_claims = StdClaims::default();
        let (payload, disclosures) =
            JwtPayload::try_new(&mut CryptoBackend::new(), input_claims, std_claims, &options).unwrap();

        assert_eq!(disclosures.len(), decisions.len());

        // hash
        assert_eq!(payload.sd_alg, "sha-256".to_string());

        // visible claims
        assert_eq!(payload.values.get("iss"), Some(&json!("https://example.com/issuer")));
        assert_eq!(payload.values.get("iat"), Some(&json!(1683000000)));
        assert_eq!(payload.values.get("exp"), Some(&json!(1883000000)));
        assert_eq!(payload.values.get("sub"), Some(&json!("user_42")));

        // assert nationalities inner items
        let nationalities = payload.values.get("nationalities").unwrap().as_array().unwrap();
        assert_eq!(nationalities.len(), 2);
        for nationality in nationalities {
            let nationality = nationality.as_object().unwrap();
            assert_eq!(nationality.len(), 1);
            assert!(nationality.contains_key("..."));
            assert!(!nationality.get("...").unwrap().as_str().unwrap().is_empty());
        }

        // verify disclosures hashes
        let root_disclosures = payload.values.get("_sd").unwrap().as_array().unwrap();
        assert_eq!(root_disclosures.len(), 8);
        for d in root_disclosures {
            assert!(!d.as_str().unwrap().is_empty());
        }
    }
}
