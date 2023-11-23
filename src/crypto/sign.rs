/// Signature Algorithm
#[derive(Debug, Copy, Clone, Default, serde::Serialize, serde::Deserialize)]
pub enum JwsAlgorithm {
    /// EdDSA using Ed25519
    ///
    /// Specified in [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)][1] and
    /// [RFC 8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)][2]
    ///
    /// [1]: https://tools.ietf.org/html/rfc8032
    /// [2]: https://tools.ietf.org/html/rfc8037
    #[default]
    Ed25519,
    /// ECDSA using P-256 and SHA-256
    ///
    /// Specified in [RFC 7518 Section 3.4: Digital Signature with ECDSA][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7518#section-3.4
    P256,
    /// ECDSA using P-384 and SHA-384
    ///
    /// Specified in [RFC 7518 Section 3.4: Digital Signature with ECDSA][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7518#section-3.4
    P384,
}

impl ToString for JwsAlgorithm {
    fn to_string(&self) -> String {
        match self {
            JwsAlgorithm::P256 => "ES256",
            JwsAlgorithm::P384 => "ES384",
            JwsAlgorithm::Ed25519 => "EdDSA",
        }
        .to_string()
    }
}
