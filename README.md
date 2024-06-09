# CryptGuard Lite

## Overview

**CryptGuard Lite** is a compact and intuitive library that wraps the `crypt_guard` crate, making its core functionalities easily accessible and manageable. This library provides essential cryptographic operations, including key generation, encryption, decryption, and digital signing, with support for multiple key variants such as Falcon and Dilithium. Its streamlined interface ensures a straightforward integration into your projects, offering robust security mechanisms with minimal complexity.

## Features

- **Key Generation**: Generate public and private key pairs for Falcon and Dilithium key variants.
- **Encryption/Decryption**: Perform encryption and decryption using AES and XChaCha20 with support for various key sizes.
- **Digital Signing**: Create and verify digital signatures using Falcon and Dilithium key pairs.
- **Support for Multiple Key Sizes**: Works with different key sizes for both Falcon and Dilithium.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
crypt_guard = "1.2.10"
cryptguard_minimal = "0.1.0"
```

## Usage

### Key Variants

The library supports two key variants:

```rust
#[derive(PartialEq, Debug)]
pub enum KeyVariants {
    Falcon,
    Dilithium
}
```

### Signing

#### Creating a Signature

```rust
use crypt_guard::KDF::Signature;
use crate::KeyVariants::Falcon;

let key_size = 512;
let (public_key, secret_key) = Sign::keypair(KeyVariants::Falcon, key_size).unwrap();

let mut guard = CryptGuard::signature(secret_key, KeyVariants::Falcon, key_size);

let data = b"your message".to_vec();
let signature = guard.signed_data(data.clone()).unwrap();
```

#### Verifying a Signature

```rust
let mut guard = CryptGuard::signature(public_key, KeyVariants::Falcon, key_size);
let verified = guard.verify(data.clone(), signature.clone()).unwrap();
assert!(verified);
```

### Encryption

#### AES Encryption

```rust
let key_size = 1024;
let passphrase = "password".to_string();
let (secret_key, public_key) = Crypto::keypair(key_size).unwrap();

let mut guard = CryptGuard::cryptography(secret_key, key_size, passphrase.clone(), None, None);
let data = b"your data".to_vec();
let (encrypted_data, cipher) = guard.aencrypt(data.clone()).unwrap();

let mut guard = CryptGuard::cryptography(public_key, key_size, passphrase.clone(), Some(cipher), None);
let decrypted_data = guard.adecrypt(encrypted_data.clone()).unwrap();
assert_eq!(data, decrypted_data);
```

#### XChaCha20 Encryption

```rust
let key_size = 1024;
let passphrase = "password".to_string();
let (secret_key, public_key) = Crypto::keypair(key_size).unwrap();

let mut guard = CryptGuard::cryptography(secret_key, key_size, passphrase.clone(), None, None);
let data = b"your data".to_vec();
let (encrypted_data, cipher, nonce) = guard.xencrypt(data.clone()).unwrap();

let mut guard = CryptGuard::cryptography(public_key, key_size, passphrase.clone(), Some(cipher), Some(nonce.clone()));
let decrypted_data = guard.xdecrypt(encrypted_data.clone(), nonce).unwrap();
assert_eq!(data, decrypted_data);
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

```

### Additional Notes

- The library depends on `crypt_guard` version `1.2.10`.
- Make sure to handle errors appropriately when integrating the library into your projects.

For more detailed usage examples and API documentation, please refer to the official `crypt_guard` crate documentation and the library's source code.

Happy coding!
```
