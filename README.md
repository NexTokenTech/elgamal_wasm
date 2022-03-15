# Elgamal Encryption Library (WASM compatible)
### To use this library,you should import elgamal_wasm as a git dependence in Cargo.toml
```
[dependencies]
 elgamal_wasm = { git = "https://github.com/NexTokenTech/elgamal_wasm.git" }
```

### Secondly, you may import crate header in your rs file.
```
 use num::BigInt;
 use crate::elgamal;
```
### Then,you could use elgamal_wasm's all pub functions,now
#### Example:
```
let pub_key:PublicKey<BigInt> = PublicKey::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
```

## Performance
To evaluate of performance of this crate and the speed of public key generation. You may run below script.
```shell
cargo bench
```

## Profiling
You may use below shell commands to run profiling code and test the performance of this crate.

<strong>Before running profiling, you need to run benchmark code first (at least on MacOS).</strong>
```shell
 sudo cargo bench --bench pubkey_benchmark -- --profile-time=10
```

## Cargo doc
### This project support cargo doc, you should tap words in Terminal like below:
```
  cargo doc --open
```
