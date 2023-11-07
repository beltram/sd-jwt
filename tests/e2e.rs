use jwt_simple::prelude::Ed25519KeyPair;
use serde_json::json;

use selective_disclosure_jwt::prelude::{Holder, Issuer, IssuerOptions, JwsAlgorithm, Verifier};

#[test]
fn e2e_test() {
    e2e().unwrap();
}

fn e2e() -> Result<(), Box<dyn std::error::Error>> {
    // === Issuer ===
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
        "/nationalities/0",
        "/nationalities/1",
    ];
    let mut issuer = Issuer::try_new()?;
    let sd_jwt = issuer.try_generate_sd_jwt(id_token, decisions, IssuerOptions::default())?;

    assert_eq!(sd_jwt.disclosures.len(), decisions.len());

    let jws = sd_jwt.jws.as_ref();
    println!("== Issuer == Payload: https://jwt.io/#id_token={jws}\n");
    println!("== Issuer == Disclosures:");

    for disclosure in &sd_jwt.disclosures {
        println!("    {disclosure}");
    }

    let serialized_sd_jwt = sd_jwt.try_serialize()?;
    println!("== Issuer == SD-JWT: {serialized_sd_jwt}");

    // === Holder ===
    let disclose = &[
        "/given_name",
        "/family_name",
        "/email",
        "/nationalities/0",
        "/nationalities/1",
    ];
    let issuer_kp = Ed25519KeyPair::from_pem(&issuer.get_signature_key())?;
    let issuer_pk = issuer_kp.public_key().to_pem();

    let holder_sd_jwt = Holder::select(&serialized_sd_jwt, disclose, JwsAlgorithm::Ed25519, &issuer_pk)?;
    assert_eq!(holder_sd_jwt.disclosures.len(), disclose.len());

    let jws = holder_sd_jwt.jws.as_ref();
    println!("\n\n== Holder == Payload: https://jwt.io/#id_token={jws}\n");
    println!("== Holder == Disclosures:");

    for disclosure in &holder_sd_jwt.disclosures {
        println!("    {disclosure}");
    }

    let serialized_holder_sd_jwt = holder_sd_jwt.try_serialize()?;
    println!("== Holder == SD-JWT: {serialized_holder_sd_jwt}");

    Verifier::verify(&serialized_holder_sd_jwt, &issuer_pk)?;
    println!("\n\n== Verifier == ✅");

    let payload = Verifier::try_read_payload(&serialized_holder_sd_jwt, &issuer_pk)?;

    assert_eq!(payload, id_token);

    Ok(())
}
