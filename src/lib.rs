//! # CryptGuard Lite
//!
//! [![Crates.io][crates-badge]][crates-url]
//! [![MIT licensed][mit-badge]][mit-url]
//! [![Documentation][doc-badge]][doc-url]
//! [![Hashnode Blog][blog-badge]][blog-url]
//! [![GitHub Library][lib-badge]][lib-link]
//!
//! [blog-badge]: https://img.shields.io/badge/blog-hashnode-lightblue.svg?style=for-the-badge
//! [blog-url]: https://blog.mm29942.com/
//! [crates-badge]: https://img.shields.io/badge/crates.io-v0.2.X-blue.svg?style=for-the-badge
//! [crates-url]: https://crates.io/crates/crypt_guard_lite
//! [mit-badge]: https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge
//! [mit-url]: https://github.com/mm9942/crypt_guard_lite/blob/main/LICENSE
//! [doc-badge]: https://img.shields.io/badge/docs-v0.2.X-yellow.svg?style=for-the-badge
//! [doc-url]: https://docs.rs/crypt_guard_lite/
//! [lib-badge]: https://img.shields.io/badge/github-crate-black.svg?style=for-the-badge
//! [lib-link]: https://github.com/mm9942/crypt_guard_lite
//!
//! ## Introduction
//!
//! CryptGuard Lite is a cryptographic library that provides a generic interface for cryptographic operations, wrapping around the `crypt_guard` crate to offer easy access to its core functionality.
//!
//! This library allows seamless interaction with underlying cryptographic operations through provided instances of type `T` (which could be the `Crypto` or `Sign` struct instances).
//! It offers methods to create and manage cryptographic operations, including keypair generation, data signing, and encryption/decryption using AES and XChaCha20 cryptographic algorithms.
//! Supported key sizes for Kyber are 1024, 768, and 512, while for Sign, Falcon supports 1024 and 512, and Dilithium supports 5, 3, and 2.
//!
//! A detached signature is a signature that is separate from the data it signs. This means that the signature is not included within the data itself but is provided separately for verification purposes. In such cases, data is returned upon verification instead of directly modifying and retrieving the signature.
//!
//! ## Examples
//!
//! ### Signing
//!
//! #### Dilithium Signing
//! ```
//! use crypt_guard_lite::{CryptGuard, KeyVariants, Sign};
//! use crypt_guard::error::SigningErr;
//!
//! pub fn main() -> Result<(), SigningErr> {
//!     let key_size = 5;
//!     let (public_key, secret_key) = Sign::keypair(KeyVariants::Dilithium, key_size).unwrap();
//!     let mut guard = CryptGuard::signature(secret_key, KeyVariants::Dilithium, key_size);
//!
//!     let data = b"hey, how are you".to_vec();
//!     let signing_data = data.clone();
//!
//!     let signature = guard.signed_data(signing_data.clone())?;
//!     println!("Signature: {:?}", signature);
//!
//!     let mut guard = CryptGuard::signature(public_key, KeyVariants::Dilithium, key_size);
//!     let opened_data = guard.open(signature.clone())?;
//!     println!("Opened data: {:?}", opened_data);
//!
//!     Ok(())
//! }
//! ```
//!
//! #### Falcon Detached Signature
//! ```
//! use crypt_guard_lite::{CryptGuard, KeyVariants, Sign};
//! use crypt_guard::error::SigningErr;
//!
//! pub fn main() -> Result<(), SigningErr> {
//!     let key_size = 512;
//!     let (public_key, secret_key) = Sign::keypair(KeyVariants::Falcon, key_size).unwrap();
//!     let mut guard = CryptGuard::signature(secret_key, KeyVariants::Falcon, key_size);
//!
//!     let data = vec![1, 2, 3, 4, 5];
//!     let signature = guard.detached(data.clone())?;
//!     println!("Signature: {:?}", signature);
//!
//!     let mut guard = CryptGuard::signature(public_key, KeyVariants::Falcon, key_size);
//!     let verified = guard.verify(data.clone(), signature.clone())?;
//!     println!("Verification: {:?}", verified);
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Encryption
//! #### AES Encryption
//! ```
//! use crypt_guard_lite::{CryptGuard, Crypto};
//! use crypt_guard::error::CryptError;
//!
//! pub fn main() -> Result<(), CryptError> {
//!     let key_size = 1024;
//!     let passphrase = "password".to_string();
//!     let (secret_key, public_key) = Crypto::keypair(key_size).unwrap();
//!     let mut guard = CryptGuard::cryptography(secret_key, key_size, passphrase.clone(), None, None);
//!
//!     let data = b"hey, how are you".to_vec();
//!     let (encrypted_data, cipher) = guard.aencrypt(data.clone()).unwrap();
//!     println!("Encrypted data: {:?}", encrypted_data);
//!
//!     let mut guard = CryptGuard::cryptography(public_key, key_size, passphrase.clone(), Some(cipher), None);
//!     let decrypted_data = guard.adecrypt(encrypted_data.clone()).unwrap();
//!     println!("Decrypted data: {:?}", decrypted_data);
//!
//!     Ok(())
//! }
//! ```
//!
//! #### XChaCha20 Encryption
//! ```
//! use crypt_guard_lite::{CryptGuard, Crypto};
//! use crypt_guard::error::CryptError;
//!
//! pub fn main() -> Result<(), CryptError> {
//!     let key_size = 1024;
//!     let passphrase = "password".to_string();
//!     let (secret_key, public_key) = Crypto::keypair(key_size).unwrap();
//!     let mut guard = CryptGuard::cryptography(secret_key, key_size, passphrase.clone(), None, None);
//!
//!     let data = b"hey, how are you".to_vec();
//!     let (encrypted_data, cipher, nonce) = guard.xencrypt(data.clone()).unwrap();
//!     println!("Encrypted data: {:?}", encrypted_data);
//!
//!     let mut guard = CryptGuard::cryptography(public_key, key_size, passphrase.clone(), Some(cipher), Some(nonce.clone()));
//!     let decrypted_data = guard.xdecrypt(encrypted_data.clone(), nonce).unwrap();
//!     println!("Decrypted data: {:?}", decrypted_data);
//!
//!     Ok(())
//! }
//! ```

use crypt_guard::{
    error::{*, CryptError},
    *
};
use crypt_guard::KDF::Signature;
use std::marker::PhantomData;
use crate::KeyVariants::Falcon;

/// KeyVariants enum represents different types of keys.
///
/// - Falcon: Uses Falcon key variant.
/// - Dilithium: Uses Dilithium key variant.
#[derive(PartialEq, Debug)]
pub enum KeyVariants {
    Falcon,
    Dilithium
}

/// Sign struct represents a signing operation
///
/// - data: The data to be signed.
/// - key: The signing key.
/// - key_variant: The variant of the key used (Falcon or Dilithium).
/// - key_size: The size of the key.
/// - signature: The generated signature.
#[derive(PartialEq, Debug)]
pub struct Sign {
    data: Vec<u8>,
    key: Vec<u8>,
    key_variant: KeyVariants,
    key_size: usize,
    signature: Vec<u8>,
}

impl Sign {
    /// Creates a new Sign instance.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The data to be signed.
    /// - `key`: Vec<u8> - The signing key.
    /// - `key_variant`: KeyVariants - The variant of the key used (Falcon or Dilithium).
    /// - `key_size`: usize - The size of the key.
    /// - `signature`: Vec<u8> - The generated signature.
    pub fn new(data: Vec<u8>, key: Vec<u8>, key_variant: KeyVariants, key_size: usize, signature: Vec<u8>) -> Self {
        Self { data, key, key_variant, key_size, signature }
    }

    /// Creates a new Sign instance with empty signature.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The data to be signed.
    /// - `key`: Vec<u8> - The signing key.
    /// - `key_variant`: KeyVariants - The variant of the key used (Falcon or Dilithium).
    /// - `key_size`: usize - The size of the key.
    pub fn from(data: Vec<u8>, key: Vec<u8>, key_variant: KeyVariants, key_size: usize) -> Self {
        let signature = Vec::new(); // Assuming empty signature initially
        Self { data, key, key_variant, key_size, signature }
    }

    /// Creates a default Sign instance.
    pub fn default() -> Self {
        Self {
            data: Vec::new(),
            key: Vec::new(),
            key_variant: KeyVariants::Falcon,
            key_size: 0,
            signature: Vec::new(),
        }
    }

    /// Generates a keypair based on the key variant and key size.
    ///
    /// # Arguments
    ///
    /// - `key_variants`: KeyVariants - The variant of the key (Falcon or Dilithium).
    /// - `key_size`: usize - The size of the key.
    ///
    /// # Returns
    ///
    /// - `Result<(Vec<u8>, Vec<u8>), SigningErr>`: The generated public and secret keys, or an error.
    pub fn keypair(key_variants: KeyVariants, key_size: usize) -> Result<(Vec<u8>, Vec<u8>), SigningErr> {
        use crypt_guard::KDF::*;

        match key_variants {
            KeyVariants::Falcon => {
                match key_size {
                    1024 => {
                        let (public, secret) = FalconKeypair!(1024);
                        Ok((public, secret))
                    },
                    512 => {
                        let (public, secret) = FalconKeypair!(512);
                        Ok((public, secret))
                    },
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }
            },
            KeyVariants::Dilithium => {
                match key_size {
                    5 => {
                        let (public, secret) = DilithiumKeypair!(5);
                        Ok((public, secret))},
                    3 => {
                        let (public, secret) = DilithiumKeypair!(3);
                        Ok((public, secret))},
                    2 => {
                        let (public, secret) = DilithiumKeypair!(2);
                        Ok((public, secret))},
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }}
            _ => {
                return Err(SigningErr::new("Invalid key variant"));
            }
        }
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    pub fn get_key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn set_key(&mut self, key: Vec<u8>, key_variant: KeyVariants, key_size: usize) {
        self.key = key;
        self.key_size = key_size;
        self.key_variant = key_variant;
    }

    pub fn get_key_variant(&self) -> &KeyVariants {
        &self.key_variant
    }

    pub fn get_key_size(&self) -> usize {
        self.key_size
    }

    pub fn get_signature(&self) -> &Vec<u8> {
        &self.signature
    }

    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

/// Crypto struct represents an encryption operation
///
/// - data: The data to be encrypted or decrypted.
/// - key: The encryption key.
/// - key_size: The size of the key.
/// - nonce: The nonce used for encryption.
/// - ciphertext: The encrypted data.
/// - passphrase: The passphrase used for encryption.
#[derive(PartialEq, Debug)]
pub struct Crypto {
    data: Vec<u8>,
    key: Vec<u8>,
    key_size: usize,
    nonce: String,
    ciphertext: Vec<u8>,
    passphrase: String,
}

impl Crypto {
    /// Creates a new Crypto instance.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The data to be encrypted or decrypted.
    /// - `key`: Vec<u8> - The encryption key.
    /// - `key_size`: usize - The size of the key.
    /// - `nonce`: String - The nonce used for encryption.
    /// - `ciphertext`: Vec<u8> - The encrypted data.
    /// - `passphrase`: String - The passphrase used for encryption.
    pub fn new(data: Vec<u8>, key: Vec<u8>, key_size: usize, nonce: String, ciphertext: Vec<u8>, passphrase: String) -> Self {
        Self { data, key, key_size, nonce, ciphertext, passphrase }
    }

    /// Creates a new Crypto instance with empty nonce and ciphertext.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The data to be encrypted or decrypted.
    /// - `key`: Vec<u8> - The encryption key.
    /// - `key_size`: usize - The size of the key.
    /// - `passphrase`: String - The passphrase used for encryption.
    pub fn from(data: Vec<u8>, key: Vec<u8>, key_size: usize, passphrase: String) -> Self {
        let nonce = String::new();
        let ciphertext = Vec::new();
        Self { data, key, key_size, nonce, ciphertext, passphrase }
    }

    /// Creates a default Crypto instance.
    pub fn default() -> Self {
        Self {
            data: Vec::new(),
            key: Vec::new(),
            key_size: 0,
            nonce: String::new(),
            ciphertext: Vec::new(),
            passphrase: String::new(),
        }
    }

    /// Generates a keypair based on the key size.
    ///
    /// # Arguments
    ///
    /// - `key_size`: usize - The size of the key.
    ///
    /// # Returns
    ///
    /// - `Result<(Vec<u8>, Vec<u8>), CryptError>`: The generated public and secret keys, or an error.
    pub fn keypair(key_size: usize) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        match key_size {
            1024 => {
                let (public, secret) = KyberKeypair!(1024);
                Ok((public, secret))
            },
            768 => {
                let (public, secret) = KyberKeypair!(768);
                Ok((public, secret))
            },
            512 => {
                let (public, secret) = KyberKeypair!(512);
                Ok((public, secret))
            },
            _ => {
                return Err(CryptError::new("Invalid key size"));
            }
        }
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    pub fn get_key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn set_key(&mut self, key: Vec<u8>, key_size: usize) {
        self.key = key;
        self.key_size = key_size
    }

    pub fn get_key_size(&self) -> usize {
        self.key_size
    }

    pub fn get_nonce(&self) -> &String {
        &self.nonce
    }

    pub fn set_nonce(&mut self, nonce: String) {
        self.nonce = nonce;
    }

    pub fn get_ciphertext(&self) -> &Vec<u8> {
        &self.ciphertext
    }

    pub fn set_ciphertext(&mut self, ciphertext: Vec<u8>) {
        self.ciphertext = ciphertext;
    }

    pub fn get_passphrase(&self) -> &String {
        &self.passphrase
    }

    pub fn set_passphrase(&mut self, passphrase: String) {
        self.passphrase = passphrase;
    }
}

/// CryptGuard struct is a generic wrapper around cryptographic operations, such as signing and encryption.
/// It allows easy interaction with the underlying cryptographic operations through the provided instance of type `T`.
///
/// This struct provides methods to create and manage cryptographic operations, including keypair generation,
/// data signing, and encryption/decryption using different cryptographic algorithms.
#[derive(PartialEq, Debug)]
pub struct CryptGuard<T> {
    instance: T,
}

impl<T> CryptGuard<T> {
    /// Creates a new CryptGuard instance.
    ///
    /// # Arguments
    ///
    /// - `instance`: T - The instance of the cryptographic operation to be wrapped.
    pub fn new(instance: T) -> Self {
        Self { instance }
    }

    /// Gets the reference to the underlying instance.
    pub fn get_instance(&self) -> &T {
        &self.instance
    }

    /// Gets a mutable reference to the underlying instance.
    pub fn get_instance_mut(&mut self) -> &mut T {
        &mut self.instance
    }
}

impl CryptGuard<Sign> {
    /// Creates a new CryptGuard instance for signing.
    ///
    /// # Arguments
    ///
    /// - `key`: Vec<u8> - The signing key.
    /// - `key_variant`: KeyVariants - The variant of the key used (Falcon or Dilithium).
    /// - `key_size`: usize - The size of the key.
    pub fn signature(key: Vec<u8>, key_variant: KeyVariants, key_size: usize) -> Self {
        let data: Vec<u8> = Vec::new();
        let sign = Sign::new(data, key, key_variant, key_size, Vec::new());
        CryptGuard::<Sign>::new(sign)
    }

    /// Signs the provided data using the configured key and key variant.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The data to be signed.
    ///
    /// # Returns
    ///
    /// - `Result<Vec<u8>, SigningErr>`: The generated signature or an error.
    pub fn signed_data(&mut self, data: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        use crypt_guard::KDF::*;

        let mut instance = self.get_instance_mut();
        let key = instance.get_key();
        let key_variant = instance.get_key_variant();
        let key_size = instance.get_key_size();

        match key_variant {
            KeyVariants::Falcon => {
                match key_size {
                    1024 => {
                        let mut sign = Signature::<Falcon1024, Message>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    },
                    512 => {
                        let mut sign = Signature::<Falcon512, Message>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    },
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }
            },
            KeyVariants::Dilithium => {
                match key_size {
                    5 => {
                        let sign = Signature::<Dilithium5, Message>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    }
                    3 => {
                        let mut sign = Signature::<Dilithium3, Message>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    }
                    2 => {
                        let mut sign = Signature::<Dilithium2, Message>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    }
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }
            }
        }
    }

    /// Creates a detached signature for the provided data using the configured key and key variant.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The data to be signed.
    ///
    /// # Returns
    ///
    /// - `Result<Vec<u8>, SigningErr>`: The generated detached signature or an error.
    pub fn detached(&mut self, data: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        use crypt_guard::KDF::*;

        let mut instance = self.get_instance_mut();
        let key = instance.get_key();
        let key_variant = instance.get_key_variant();
        let key_size = instance.get_key_size();

        match key_variant {
            KeyVariants::Falcon => {
                match key_size {
                    1024 => {
                        let mut sign = Signature::<Falcon1024, Detached>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    },
                    512 => {
                        let mut sign = Signature::<Falcon512, Detached>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    },
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }
            },
            KeyVariants::Dilithium => {
                match key_size {
                    5 => {
                        let sign = Signature::<Dilithium5, Detached>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    }
                    3 => {
                        let mut sign = Signature::<Dilithium3, Detached>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    }
                    2 => {
                        let mut sign = Signature::<Dilithium2, Detached>::new();
                        let signature = sign.signature(data.to_owned(), instance.get_key().to_owned())?;
                        instance.set_signature(signature.to_owned());
                        Ok(signature.to_owned())
                    }
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }
            }
        }
    }

    /// Verifies a detached signature against the provided data using the configured key and key variant.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The data to verify.
    /// - `signature`: Vec<u8> - The detached signature to verify.
    ///
    /// # Returns
    ///
    /// - `Result<bool, SigningErr>`: `true` if the signature is valid, `false` otherwise, or an error.
    pub fn verify(&mut self, data: Vec<u8>, signature: Vec<u8>) -> Result<bool, SigningErr> {
        use crypt_guard::KDF::*;

        {
            let mut instance = self.get_instance_mut();
            let _ = instance.set_data(data.to_owned());
            let _ = instance.set_signature(signature.to_owned());
        }

        let mut instance = self.get_instance_mut();
        let key = instance.get_key();
        let key_variant = instance.get_key_variant();
        let key_size = instance.get_key_size();

        match key_variant {
            KeyVariants::Falcon => {
                match key_size {
                    1024 => {
                        let mut sign = Signature::<Falcon1024, Detached>::new();
                        let verified = sign.verify(data.to_owned(), signature, instance.get_key().to_owned())?;
                        Ok(verified)
                    },
                    512 => {
                        let mut sign = Signature::<Falcon512, Detached>::new();
                        let verified = sign.verify(data.to_owned(), signature, instance.get_key().to_owned())?;
                        Ok(verified)
                    },
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }
            },
            KeyVariants::Dilithium => {
                match key_size {
                    5 => {
                        let sign = Signature::<Dilithium5, Detached>::new();
                        let verified = sign.verify(data.to_owned(), signature, instance.get_key().to_owned())?;
                        Ok(verified)
                    }
                    3 => {
                        let mut sign = Signature::<Dilithium3, Detached>::new();
                        let verified = sign.verify(data.to_owned(), signature, instance.get_key().to_owned())?;
                        Ok(verified)
                    }
                    2 => {
                        let mut sign = Signature::<Dilithium2, Detached>::new();
                        let verified = sign.verify(data.to_owned(), signature, instance.get_key().to_owned())?;
                        Ok(verified)
                    }
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }
            }
        }
    }

    /// Opens a signed message to extract the original data.
    ///
    /// # Arguments
    ///
    /// - `signature`: Vec<u8> - The signed message.
    ///
    /// # Returns
    ///
    /// - `Result<Vec<u8>, SigningErr>`: The original data or an error.
    pub fn open(&mut self, signature: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        use crypt_guard::KDF::*;

        {
            let mut instance = self.get_instance_mut();
            instance.set_signature(signature.as_slice().to_owned());
        }

        let instance = self.get_instance_mut();
        let key = instance.get_key();
        let key_variant = instance.get_key_variant();
        let key_size = instance.get_key_size();

        match key_variant {
            KeyVariants::Falcon => {
                match key_size {
                    1024 => {
                        let mut sign = Signature::<Falcon1024, Message>::new();
                        let data = sign.open(signature.to_owned(), instance.get_key().to_owned())?;
                        instance.set_data(data.to_owned());
                        Ok(signature.to_owned())
                    },
                    512 => {
                        let mut sign = Signature::<Falcon512, Message>::new();
                        let data = sign.open(signature.to_owned(), instance.get_key().to_owned())?;
                        instance.set_data(data.to_owned());
                        Ok(signature.to_owned())
                    },
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }
            },
            KeyVariants::Dilithium => {
                match key_size {
                    5 => {
                        let sign = Signature::<Dilithium5, Message>::new();
                        let data = sign.open(signature.to_owned(), instance.get_key().to_owned())?;
                        instance.set_data(data.to_owned());
                        Ok(signature.to_owned())
                    }
                    3 => {
                        let mut sign = Signature::<Dilithium3, Message>::new();
                        let data = sign.open(signature.to_owned(), instance.get_key().to_owned())?;
                        instance.set_data(data.to_owned());
                        Ok(signature.to_owned())
                    }
                    2 => {
                        let mut sign = Signature::<Dilithium2, Message>::new();
                        let data = sign.open(signature.to_owned(), instance.get_key().to_owned())?;
                        instance.set_data(data.to_owned());
                        Ok(signature.to_owned())
                    }
                    _ => {
                        return Err(SigningErr::new("Invalid key size"));
                    }
                }
            }
        }
    }
}

impl CryptGuard<Crypto> {
    /// Creates a new CryptGuard instance for encryption.
    ///
    /// # Arguments
    ///
    /// - `key`: Vec<u8> - The encryption key.
    /// - `key_size`: usize - The size of the key.
    /// - `passphrase`: String - The passphrase used for encryption.
    /// - `ciphertext`: Option<Vec<u8>> - The encrypted data (optional).
    /// - `nonce`: Option<String> - The nonce used for encryption (optional).
    pub fn cryptography(key: Vec<u8>, key_size: usize, passphrase: String, ciphertext: Option<Vec<u8>>, nonce: Option<String>) -> Self {
        let data: Vec<u8> = Vec::new();
        let nonce = nonce.unwrap_or_else(|| String::new());
        let ciphertext = ciphertext.unwrap_or_else(|| Vec::new());
        let cryptography = Crypto::new(data, key, key_size, nonce, ciphertext, passphrase);
        CryptGuard::<Crypto>::new(cryptography)
    }

    /// AES Encryption.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The data to be encrypted.
    ///
    /// # Returns
    ///
    /// - `Result<(Vec<u8>, Vec<u8>), CryptError>`: The encrypted data and the cipher, or an error.
    pub fn aencrypt(&mut self, data: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let mut instance = self.get_instance_mut();
        let key_size = instance.get_key_size();
        let passphrase = instance.get_passphrase();
        let key = instance.get_key();

        match key_size {
            1024 => {
                Encryption!(key.to_owned(), 1024, data.to_owned(), passphrase.as_str(), AES)
            },
            768 => {
                Encryption!(key.to_owned(), 768, data.to_owned(), passphrase.as_str(), AES)
            },
            512 => {
                Encryption!(key.to_owned(), 512, data.to_owned(), passphrase.as_str(), AES)
            },
            _ => {
                return Err(CryptError::new("Invalid key size"));
            }
        }
    }

    /// XChaCha20 Encryption.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The data to be encrypted.
    ///
    /// # Returns
    ///
    /// - `Result<(Vec<u8>, Vec<u8>, String), CryptError>`: The encrypted data, the cipher, and the nonce, or an error.
    pub fn xencrypt(&mut self, data: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, String), CryptError> {
        let mut instance = self.get_instance_mut();
        let key_size = instance.get_key_size();
        let passphrase = instance.get_passphrase();
        let key = instance.get_key();

        match key_size {
            1024 => {
                let mut encryptor = Kyber::<Encryption, Kyber1024, Files, XChaCha20>::new(key.to_owned(), None)?;
                let (encrypt_message, cipher) = &encryptor.encrypt_data(data.to_owned(), &passphrase)?;
                let nonce = encryptor.get_nonce()?;
                let _ = instance.set_nonce(nonce.to_owned());
                Ok((encrypt_message.to_owned(), cipher.to_owned(), nonce.to_owned()))            },
            768 => {
                let mut encryptor = Kyber::<Encryption, Kyber768, Files, XChaCha20>::new(key.to_owned(), None)?;
                let (encrypt_message, cipher) = &encryptor.encrypt_data(data.to_owned(), &passphrase)?;
                let nonce = encryptor.get_nonce()?;
                let _ = instance.set_nonce(nonce.to_owned());
                Ok((encrypt_message.to_owned(), cipher.to_owned(), nonce.to_owned()))            },
            512 => {
                let mut encryptor = Kyber::<Encryption, Kyber512, Files, XChaCha20>::new(key.to_owned(), None)?;
                let (encrypt_message, cipher) = &encryptor.encrypt_data(data.to_owned(), &passphrase)?;
                let nonce = encryptor.get_nonce()?;
                let _ = instance.set_nonce(nonce.to_owned());
                Ok((encrypt_message.to_owned(), cipher.to_owned(), nonce.to_owned()))
            },
            _ => {
                return Err(CryptError::new("Invalid key size"));
            }
        }
    }

    /// AES Decryption.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The encrypted data.
    ///
    /// # Returns
    ///
    /// - `Result<Vec<u8>, CryptError>`: The decrypted data or an error.
    pub fn adecrypt(&mut self, data: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        let mut instance = self.get_instance_mut();
        let key_size = instance.get_key_size();
        let passphrase = instance.get_passphrase();
        let key = instance.get_key();
        let ciphertext = instance.get_ciphertext();

        match key_size {
            1024 => {
                Decryption!(key.to_owned(), 1024, data.to_owned(), passphrase.as_str(), ciphertext.to_owned(), AES)
            },
            768 => {
                Decryption!(key.to_owned(), 768, data.to_owned(), passphrase.as_str(), ciphertext.to_owned(), AES)
            },
            512 => {
                Decryption!(key.to_owned(), 512, data.to_owned(), passphrase.as_str(), ciphertext.to_owned(), AES)
            },
            _ => {
                return Err(CryptError::new("Invalid key size"));
            }
        }
    }

    /// XChaCha20 Decryption.
    ///
    /// # Arguments
    ///
    /// - `data`: Vec<u8> - The encrypted data.
    /// - `nonce`: String - The nonce used for encryption.
    ///
    /// # Returns
    ///
    /// - `Result<Vec<u8>, CryptError>`: The decrypted data or an error.
    pub fn xdecrypt(&mut self, data: Vec<u8>, nonce: String) -> Result<Vec<u8>, CryptError> {
        {
            let mut instance = self.get_instance_mut();
            let _ = instance.set_nonce(nonce.to_owned());
        }

        let mut instance = self.get_instance_mut();
        let key_size = instance.get_key_size();
        let passphrase = instance.get_passphrase();
        let key = instance.get_key();
        let ciphertext = instance.get_ciphertext();

        match key_size {
            1024 => {
                let mut decryptor = Kyber::<Decryption, Kyber1024, Files, XChaCha20>::new(key.to_owned(), Some(nonce))?;
                let data = decryptor.decrypt_data(data.to_owned(), &passphrase, ciphertext.to_owned())?;
                Ok(data.to_owned())
            },
            768 => {
                let mut decryptor = Kyber::<Decryption, Kyber768, Files, XChaCha20>::new(key.to_owned(), Some(nonce))?;
                let data = decryptor.decrypt_data(data.to_owned(), &passphrase, ciphertext.to_owned())?;
                Ok(data.to_owned())
            },
            512 => {
                let mut decryptor = Kyber::<Decryption, Kyber512, Files, XChaCha20>::new(key.to_owned(), Some(nonce))?;
                let data = decryptor.decrypt_data(data.to_owned(), &passphrase, ciphertext.to_owned())?;
                Ok(data.to_owned())
            },
            _ => {
                return Err(CryptError::new("Invalid key size"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypt_guard::KDF::*;

    #[test]
    fn test_signed_data() -> Result<(), SigningErr> {
        let key_size = 5;
        let (public_key, secret_key) = {
            println!("Generating keypair...");
            Sign::keypair(KeyVariants::Dilithium, key_size).unwrap()
        };

        println!("Secret Key: {:?}", secret_key);
        println!("Public Key: {:?}", public_key);

        let mut guard = {
            println!("Creating CryptGuard with secret key...");
            CryptGuard::signature(secret_key, KeyVariants::Dilithium, key_size)
        };

        let data = b"hey, how are you".to_vec();
        let signing_data = data.clone();

        println!("Signing data: {:?}", signing_data);
        let signature = guard.signed_data(signing_data.clone())?;

        println!("Signature: {:?}", signature);

        assert_eq!(guard.get_instance().get_key_variant(), &KeyVariants::Dilithium);
        assert_eq!(guard.get_instance().get_key_size(), key_size);

        let mut guard = {
            println!("Creating CryptGuard with public key...");
            CryptGuard::signature(public_key, KeyVariants::Dilithium, key_size)
        };
        let opened_data = guard.open(signature.clone())?;

        println!("Opened data: {:?}", opened_data);

        assert!(!signature.is_empty());
        let data = guard.get_instance().get_data();
        assert_eq!(signing_data, *data);
        Ok(())
    }

    #[test]
    fn test_detached_signature() {
        let key_size = 512;
        let (public_key, secret_key) = {
            Sign::keypair(KeyVariants::Falcon, key_size).unwrap()
        };

        let mut guard = { CryptGuard::signature(secret_key, KeyVariants::Falcon, key_size) };

        let data = vec![1, 2, 3, 4, 5];
        let signature = {
            guard.detached(data.clone()).unwrap()
        };

        let mut guard = { CryptGuard::signature(public_key, KeyVariants::Falcon, key_size) };
        let verified = guard.verify(data.clone(), signature.clone()).unwrap();

        assert!(verified);
        assert!(!signature.is_empty());
        assert_eq!(guard.get_instance().get_key_variant(), &KeyVariants::Falcon);
        assert_eq!(guard.get_instance().get_key_size(), key_size);
    }

    #[test]
    fn test_aencryption() {
        let key_size = 1024;
        let passphrase = "password".to_string();
        let (secret_key, public_key) = {
            Crypto::keypair(key_size).unwrap()
        };

        let mut guard = { CryptGuard::cryptography(secret_key, key_size, passphrase.clone(), None, None) };

        let data = b"hey, how are you".to_vec();
        let (encrypted_data, cipher) = {
            guard.aencrypt(data.clone()).unwrap()
        };

        let mut guard = { CryptGuard::cryptography(public_key, key_size, passphrase.clone(), Some(cipher), None) };
        let decrypted_data = guard.adecrypt(encrypted_data.clone()).unwrap();

        assert_eq!(data, decrypted_data);
    }

    #[test]
    fn test_xencryption() {
        let key_size = 1024;
        let passphrase = "password".to_string();
        let (secret_key, public_key) = {
            Crypto::keypair(key_size).unwrap()
        };

        let mut guard = { CryptGuard::cryptography(secret_key, key_size, passphrase.clone(), None, None) };

        let data = b"hey, how are you".to_vec();
        let (encrypted_data, cipher, nonce) = {
            guard.xencrypt(data.clone()).unwrap()
        };

        let mut guard = { CryptGuard::cryptography(public_key, key_size, passphrase.clone(), Some(cipher), Some(nonce.clone())) };
        let decrypted_data = guard.xdecrypt(encrypted_data.clone(), nonce).unwrap();

        assert_eq!(data, decrypted_data);
    }
}
