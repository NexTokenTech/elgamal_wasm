# elgamal_capsule
### At first,you should import elgamal_capsule as a git dependence in Cargo.toml
```
[dependencies]
 elgamal_capsule = { git = "https://github.com/NexTokenTech/elgamal_capsule.git" }
```
### And import num base library in Cargo.toml too.
```
[dependencies]
 elgamal_capsule = { git = "https://github.com/NexTokenTech/elgamal_capsule
 num = { version = "0.3.1"}
```
### Secondly,you should import crate header in your rs file.
```
 use num::BigInt;
 use crate::elgamal;
```
### Then,you could use elgamal_capsule's all pub functions,now
#### Example:
```
 elgamal::generate_pub_key(&BigInt::from(3989),32,32);
```
