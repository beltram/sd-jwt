use crate::crypto::{
    error::{CryptoError, CryptoResult},
    Salt,
};

/// A reusable backend for all crypto related stuff
pub struct CryptoBackend<const SALT_SIZE: usize = { super::DEFAULT_SALT_SIZE }> {
    rng: std::sync::RwLock<rand_chacha::ChaCha20Rng>,
}

impl<const SALT_SIZE: usize> CryptoBackend<SALT_SIZE> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        use rand_chacha::rand_core::SeedableRng as _;
        let rng = rand_chacha::ChaCha20Rng::from_entropy();
        let rng = std::sync::RwLock::new(rng);
        Self { rng }
    }

    pub fn new_salt(&mut self) -> CryptoResult<Salt<SALT_SIZE>> {
        #[cfg(not(feature = "e2e-test"))]
        {
            Salt::try_new(&mut self.rng.write().map_err(|_| CryptoError::PoisonError)?)
        }
        #[cfg(feature = "e2e-test")]
        {
            self.new_python_salt()
        }
    }

    /// In order to test against the reference implementation test vectors written in Python
    #[cfg(feature = "e2e-test")]
    fn new_python_salt(&mut self) -> CryptoResult<Salt<SALT_SIZE>> {
        let mut rnd = rand_python::PythonRandom::new(rand_python::MersenneTwister::new());
        rnd.seed_u32(0);
        let mut salt = [0u8; SALT_SIZE];
        for (i, _) in (0..SALT_SIZE).enumerate() {
            let r: u8 = rnd.getrandbits(8).try_into().unwrap();
            salt[i] = r;
        }
        Ok(Salt(salt))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn python_salt_should_be_deterministic() {
        let mut backend: CryptoBackend<16> = CryptoBackend::new();
        let salt = backend.new_salt().unwrap();
        let salt = hex::encode(salt.0);
        assert_eq!("d862c2e36b0a42f7827c67ebc8d44df7", &salt);
    }
}
