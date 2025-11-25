// Copyright 2024 The Tink-Rust Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! X-AES-GCM based implementation of the [`tink_core::Aead`] trait.

use std::convert::TryInto;
use tink_core::{utils::wrap_err, TinkError};
use xaes_256_gcm::{
    aead::{Aead, KeyInit, Payload},
    Nonce, Xaes256Gcm,
};

/// The size of the X-AES-GCM key in bytes (256 bits).
pub const X_AES_GCM_KEY_SIZE: usize = 32;
/// Minimum salt size in bytes.
pub const X_AES_GCM_MIN_SALT_SIZE: usize = 8;
/// Maximum salt size in bytes.
pub const X_AES_GCM_MAX_SALT_SIZE: usize = 12;
/// The tag size that X-AES-GCM produces.
pub const X_AES_GCM_TAG_SIZE: usize = 16;
/// The nonce size for X-AES-GCM is 24 bytes (192 bits).
const X_AES_GCM_NONCE_SIZE: usize = 24;

/// `XAesGcm` is an implementation of the [`tink_core::Aead`] trait using X-AES-GCM.
///
/// X-AES-GCM is an extended-nonce variant of AES-GCM that uses a 192-bit nonce constructed
/// from a per-message salt and a counter. This allows for safe encryption of large amounts
/// of data without nonce reuse concerns.
#[derive(Clone)]
pub struct XAesGcm {
    cipher: Xaes256Gcm,
    salt_size: usize,
}

impl XAesGcm {
    /// Create a new [`XAesGcm`] instance.
    ///
    /// # Arguments
    /// * `key` - The 256-bit (32-byte) AES key
    /// * `salt_size` - The size of the salt to use for nonce generation (8-12 bytes)
    pub fn new(key: &[u8], salt_size: usize) -> Result<XAesGcm, TinkError> {
        if key.len() != X_AES_GCM_KEY_SIZE {
            return Err(format!(
                "XAesGcm: invalid key size {} (want {})",
                key.len(),
                X_AES_GCM_KEY_SIZE
            )
            .into());
        }
        if salt_size < X_AES_GCM_MIN_SALT_SIZE || salt_size > X_AES_GCM_MAX_SALT_SIZE {
            return Err(format!(
                "XAesGcm: invalid salt size {} (want {}-{})",
                salt_size, X_AES_GCM_MIN_SALT_SIZE, X_AES_GCM_MAX_SALT_SIZE
            )
            .into());
        }
        // Safety: We've already verified key is exactly X_AES_GCM_KEY_SIZE bytes
        let key_ref = key
            .try_into()
            .map_err(|_| TinkError::new("XAesGcm: key conversion failed"))?;
        let cipher = Xaes256Gcm::new(key_ref);
        Ok(XAesGcm { cipher, salt_size })
    }
}

impl tink_core::Aead for XAesGcm {
    /// Encrypt `pt` with `aad` as additional authenticated data.
    ///
    /// The resulting ciphertext consists of:
    /// 1. A random salt of `salt_size` bytes
    /// 2. The actual ciphertext (including authentication tag)
    fn encrypt(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        // Generate random salt
        let salt = tink_core::subtle::random::get_random_bytes(self.salt_size);

        // X-AES-GCM uses a 24-byte nonce. We construct it by placing the salt
        // in the first portion and padding the rest with zeros.
        let mut nonce_bytes = [0u8; X_AES_GCM_NONCE_SIZE];
        nonce_bytes[..self.salt_size].copy_from_slice(&salt);
        let nonce: &Nonce = (&nonce_bytes)
            .try_into()
            .map_err(|_| TinkError::new("XAesGcm: nonce conversion failed"))?;

        let payload = Payload { msg: pt, aad };
        let ct = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|e| wrap_err("XAesGcm", e))?;

        // Prepend salt to ciphertext
        let mut ret = Vec::with_capacity(self.salt_size + ct.len());
        ret.extend_from_slice(&salt);
        ret.extend_from_slice(&ct);
        Ok(ret)
    }

    /// Decrypt `ct` with `aad` as the additional authenticated data.
    fn decrypt(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        if ct.len() < self.salt_size + X_AES_GCM_TAG_SIZE {
            return Err("XAesGcm: ciphertext too short".into());
        }

        // Extract salt from the beginning of the ciphertext
        let salt = &ct[..self.salt_size];

        // Reconstruct the 24-byte nonce using the salt
        let mut nonce_bytes = [0u8; X_AES_GCM_NONCE_SIZE];
        nonce_bytes[..self.salt_size].copy_from_slice(salt);
        let nonce: &Nonce = (&nonce_bytes)
            .try_into()
            .map_err(|_| TinkError::new("XAesGcm: nonce conversion failed"))?;

        let payload = Payload {
            msg: &ct[self.salt_size..],
            aad,
        };

        let pt = self
            .cipher
            .decrypt(nonce, payload)
            .map_err(|e| wrap_err("XAesGcm", e))?;
        Ok(pt)
    }
}
