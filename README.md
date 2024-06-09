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
crypt_guard_lite = "0.2.2"
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

### Key Generation

#### Generating Keys

```rust
use crypt_guard_lite::{CryptGuard, KeyVariants, Sign, Crypto};
use crypt_guard::error::{SigningErr, CryptError};

// Dilithium key pair
let key_size = 5;
let (dilithium_public_key, dilithium_secret_key) = Sign::keypair(KeyVariants::Dilithium, key_size).unwrap();

// Falcon key pair
let key_size = 512;
let (falcon_public_key, falcon_secret_key) = Sign::keypair(KeyVariants::Falcon, key_size).unwrap();

// Kyber key pair
let key_size = 1024;
let (kyber_public_key, kyber_secret_key) = Crypto::keypair(key_size).unwrap();
```

### Encryption

#### AES Encryption

```rust
use crypt_guard_lite::{CryptGuard, Crypto};
use crypt_guard::error::CryptError;

pub fn main() -> Result<(), CryptError> {
    let key_size = 1024;
    let passphrase = "password".to_string();
    let (secret_key, public_key) = Crypto::keypair(key_size).unwrap();

    let mut guard = CryptGuard::cryptography(secret_key, key_size, passphrase.clone(), None, None);
    let data = b"hey, how are you".to_vec();
    let (encrypted_data, cipher) = guard.aencrypt(data.clone()).unwrap();
    println!("Encrypted data: {:?}", encrypted_data);

    let mut guard = CryptGuard::cryptography(public_key, key_size, passphrase.clone(), Some(cipher), None);
    let decrypted_data = guard.adecrypt(encrypted_data.clone()).unwrap();
    println!("Decrypted data: {:?}", decrypted_data);

    Ok(())
}
```

#### XChaCha20 Encryption

```rust
use crypt_guard_lite::{CryptGuard, Crypto};
use crypt_guard::error::CryptError;

pub fn main() -> Result<(), CryptError> {
    let key_size = 1024;
    let passphrase = "password".to_string();
    let (secret_key, public_key) = Crypto::keypair(key_size).unwrap();

    let mut guard = CryptGuard::cryptography(secret_key, key_size, passphrase.clone(), None, None);
    let data = b"hey, how are you".to_vec();
    let (encrypted_data, cipher, nonce) = guard.xencrypt(data.clone()).unwrap();
    println!("Encrypted data: {:?}", encrypted_data);

    let mut guard = CryptGuard::cryptography(public_key, key_size, passphrase.clone(), Some(cipher), Some(nonce.clone()));
    let decrypted_data = guard.xdecrypt(encrypted_data.clone(), nonce).unwrap();
    println!("Decrypted data: {:?}", decrypted_data);

    Ok(())
}
```

### Signing

#### Creating a Signature with Dilithium

```rust
use crypt_guard_lite::{CryptGuard, KeyVariants, Sign};
use crypt_guard::error::SigningErr;

pub fn main() -> Result<(), SigningErr> {
    let key_size = 5;
    let (public_key, secret_key) = Sign::keypair(KeyVariants::Dilithium, key_size).unwrap();
    let mut guard = CryptGuard::signature(secret_key, KeyVariants::Dilithium, key_size);

    let data = b"hey, how are you".to_vec();
    let signing_data = data.clone();

    let signature = guard.signed_data(signing_data.clone())?;
    println!("Signature: {:?}", signature);

    let mut guard = CryptGuard::signature(public_key, KeyVariants::Dilithium, key_size);
    let opened_data = guard.open(signature.clone())?;
    println!("Opened data: {:?}", opened_data);

    Ok(())
}
```

#### Creating a Detached Signature with Falcon

```rust
use crypt_guard_lite::{CryptGuard, KeyVariants, Sign};
use crypt_guard::error::SigningErr;

pub fn main() -> Result<(), SigningErr> {
    let key_size = 512;
    let (public_key, secret_key) = Sign::keypair(KeyVariants::Falcon, key_size).unwrap();
    let mut guard = CryptGuard::signature(secret_key, KeyVariants::Falcon, key_size);

    let data = vec![1, 2, 3, 4, 5];
    let signature = guard.detached(data.clone())?;
    println!("Signature: {:?}", signature);

    let mut guard = CryptGuard::signature(public_key, KeyVariants::Falcon, key_size);
    let verified = guard.verify(data.clone(), signature.clone())?;
    println!("Verification: {:?}", verified);

    Ok(())
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
