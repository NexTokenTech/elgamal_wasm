use rand_core::RngCore;

/// Error for key generation.
#[derive(Debug, Clone)]
pub struct GenError;

/// Type alias for key generation result.
#[allow(unused)]
pub type GenResult<T> = std::result::Result<T, GenError>;

/// init private key structure for elgamal encryption.
#[derive(Debug, Clone)]
pub struct PrivateKey<I> {
    pub p: I,
    pub g: I,
    pub x: I,
    pub bit_length: u32,
}

/// Init public key structure for elgamal encryption.
#[derive(Debug, Clone)]
pub struct PublicKey<I> {
    pub p: I,
    pub g: I,
    pub h: I,
    pub bit_length: u32,
}

/// A trait to use a RNG and elgamal key to encrypt plaintext to UTF_16LE string.
pub trait Encryption<I> {
    fn encrypt<R: RngCore>(&self, key: &PublicKey<I>, rng: &mut R) -> String;
}
