# elgamal_wasm
### At first,you should import elgamal_wasm as a git dependence in Cargo.toml
```
[dependencies]
 elgamal_wasm = { git = "https://github.com/NexTokenTech/elgamal_wasm.git" }
```
### And import num base library in Cargo.toml too.
```
[dependencies]
 elgamal_wasm = { git = "https://github.com/NexTokenTech/elgamal_wasm
 num = { version = "0.3.1"}
```
### Secondly,you should import crate header in your rs file.
```
 use num::BigInt;
 use crate::elgamal;
```
### Then,you could use elgamal_wasm's all pub functions,now
#### Example:
```
 elgamal::generate_pub_key(&BigInt::from(3989),32,32);
```

## Cargo doc
### This project support cargo doc, you should tap words in Terminal like below:
```
  cargo doc --open
```
