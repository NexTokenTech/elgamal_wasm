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
