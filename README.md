# CryptGuard Lite

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Documentation][doc-badge]][doc-url]
[![Hashnode Blog][blog-badge]][blog-url]
[![GitHub Library][lib-badge]][lib-link]

[blog-badge]: https://img.shields.io/badge/blog-hashnode-lightblue.svg?style=for-the-badge
[blog-url]: https://blog.mm29942.com/
[crates-badge]: https://img.shields.io/badge/crates.io-v0.2.X-blue.svg?style=for-the-badge
[crates-url]: https://crates.io/crates/crypt_guard_lite
[mit-badge]: https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge
[mit-url]: https://github.com/mm9942/crypt_guard_lite/blob/main/LICENSE
[doc-badge]: https://img.shields.io/badge/docs-v0.2.X-yellow.svg?style=for-the-badge
[doc-url]: https://docs.rs/crypt_guard_lite/
[lib-badge]: https://img.shields.io/badge/github-crate-black.svg?style=for-the-badge
[lib-link]: https://github.com/mm9942/crypt_guard_lite


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
crypt_guard_lite = "0.2.1"
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