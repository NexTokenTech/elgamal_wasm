use codec::{Decode, Encode};
use sp_core::U256;

/// The raw public key type use bytes string.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct RawPublicKey {
    pub p: U256,
    pub g: U256,
    pub h: U256,
    pub bit_length: u32,
}
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

/// To and from raw bytes of a public key. Use little endian byte order by default.
pub trait RawBytes<I> {
    fn to_bytes(self) -> RawPublicKey;
    fn from_bytes(raw_key: &RawPublicKey) -> Self;
}

/// Generate a seed data slice from a key data.
pub trait Seed {
    fn yield_seed_slice(&self) -> Vec<u32>;
}

/// Rust generator is not yet stable, use self-defined generator trait.
pub trait KeyGenerator<I> {
    /// Use current data slices as seed and generate a new public key.
    fn yield_pubkey(&self, bit_length: u32) -> Self;
}
