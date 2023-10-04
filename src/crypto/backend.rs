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
        // TODO: do we need to reseed RNG every time to have truly independent salts ?
        let mut rng = self.rng.write().map_err(|_| CryptoError::PoisonError)?;
        Salt::try_new(&mut rng)
    }
}
