use crate::prelude::{SdjError, SdjResult};
use jwt_simple::prelude::{EdwardCurve, EllipticCurve, EllipticCurveKeyType, OctetKeyPairType};

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

/// Supported elliptic curve algorithms
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum JwsEcAlgorithm {
    /// P-256
    P256,
    /// P-384
    P384,
}

impl JwsEcAlgorithm {
    /// For JWK 'crv' field
    pub fn curve(&self) -> EllipticCurve {
        match self {
            JwsEcAlgorithm::P256 => EllipticCurve::P256,
            JwsEcAlgorithm::P384 => EllipticCurve::P384,
        }
    }

    /// For JWK 'crv' field
    pub fn kty(&self) -> EllipticCurveKeyType {
        EllipticCurveKeyType::EC
    }
}

impl TryFrom<JwsAlgorithm> for JwsEcAlgorithm {
    type Error = SdjError;

    fn try_from(alg: JwsAlgorithm) -> SdjResult<Self> {
        match alg {
            JwsAlgorithm::P256 => Ok(Self::P256),
            JwsAlgorithm::P384 => Ok(Self::P384),
            JwsAlgorithm::Ed25519 => Err(SdjError::ImplementationError),
        }
    }
}

impl From<JwsEcAlgorithm> for JwsAlgorithm {
    fn from(alg: JwsEcAlgorithm) -> Self {
        match alg {
            JwsEcAlgorithm::P256 => Self::P256,
            JwsEcAlgorithm::P384 => Self::P384,
        }
    }
}

/// Supported edward curve algorithms
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum JwsEdAlgorithm {
    /// Ed25519
    Ed25519,
}

impl JwsEdAlgorithm {
    /// For JWK 'crv' field
    pub fn curve(&self) -> EdwardCurve {
        match self {
            JwsEdAlgorithm::Ed25519 => EdwardCurve::Ed25519,
        }
    }

    /// For JWK 'crv' field
    pub fn kty(&self) -> OctetKeyPairType {
        OctetKeyPairType::OctetKeyPair
    }
}

impl TryFrom<JwsAlgorithm> for JwsEdAlgorithm {
    type Error = SdjError;

    fn try_from(alg: JwsAlgorithm) -> SdjResult<Self> {
        match alg {
            JwsAlgorithm::Ed25519 => Ok(Self::Ed25519),
            JwsAlgorithm::P256 | JwsAlgorithm::P384 => Err(SdjError::ImplementationError),
        }
    }
}

impl From<JwsEdAlgorithm> for JwsAlgorithm {
    fn from(alg: JwsEdAlgorithm) -> Self {
        match alg {
            JwsEdAlgorithm::Ed25519 => Self::Ed25519,
        }
    }
}
