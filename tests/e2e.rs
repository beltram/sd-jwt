use serde_json::json;

use selective_disclosure_jwt::prelude::{Issuer, IssuerOptions};

#[test]
fn e2e_test() {
    e2e().unwrap();
}

fn e2e() -> Result<(), Box<dyn std::error::Error>> {
    // Issuer
    let id_token = json!({
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
    let mut issuer = Issuer::try_new()?;
    let sdjwt = issuer.try_generate_sdjwt(id_token, decisions, IssuerOptions::default())?;

    let serialized_sdjwt = sdjwt.try_serialize()?;
    println!("== Issued SD-JWT: {serialized_sdjwt}");

    // Holder

    Ok(())
}
