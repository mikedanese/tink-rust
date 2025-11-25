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

//! Key manager for X-AES-GCM keys.

use crate::subtle;
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::prost::Message;

/// Maximal version of X-AES-GCM keys.
pub const X_AES_GCM_KEY_VERSION: u32 = 0;
/// Type URL of X-AES-GCM keys that Tink supports.
pub const X_AES_GCM_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.XAesGcmKey";

/// `XAesGcmKeyManager` is an implementation of the `tink_core::registry::KeyManager` trait.
/// It generates new [`XAesGcmKey`](tink_proto::XAesGcmKey) keys and produces new instances of
/// [`subtle::XAesGcm`].
#[derive(Default)]
pub(crate) struct XAesGcmKeyManager {}

impl tink_core::registry::KeyManager for XAesGcmKeyManager {
    /// Create a [`subtle::XAesGcm`] for the given serialized [`tink_proto::XAesGcmKey`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("XAesGcmKeyManager: invalid key".into());
        }
        let key = tink_proto::XAesGcmKey::decode(serialized_key)
            .map_err(|e| wrap_err("XAesGcmKeyManager: invalid key", e))?;
        validate_key(&key)?;

        let params = key
            .params
            .as_ref()
            .ok_or_else(|| TinkError::new("XAesGcmKeyManager: missing params"))?;

        match subtle::XAesGcm::new(&key.key_value, params.salt_size as usize) {
            Ok(p) => Ok(tink_core::Primitive::Aead(Box::new(p))),
            Err(e) => Err(wrap_err(
                "XAesGcmKeyManager: cannot create new primitive",
                e,
            )),
        }
    }

    /// Create a new key according to specification the given serialized
    /// [`tink_proto::XAesGcmKeyFormat`].
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("XAesGcmKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::XAesGcmKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("XAesGcmKeyManager: invalid key format", e))?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("XAesGcmKeyManager: invalid key format", e))?;

        // X-AES-GCM always uses a 256-bit (32-byte) key
        let key_value = tink_core::subtle::random::get_random_bytes(subtle::X_AES_GCM_KEY_SIZE);
        let key = tink_proto::XAesGcmKey {
            version: X_AES_GCM_KEY_VERSION,
            params: key_format.params.clone(),
            key_value,
        };
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("XAesGcmKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        X_AES_GCM_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`tink_proto::XAesGcmKey`].
fn validate_key(key: &tink_proto::XAesGcmKey) -> Result<(), TinkError> {
    tink_core::keyset::validate_key_version(key.version, X_AES_GCM_KEY_VERSION)
        .map_err(|e| wrap_err("XAesGcmKeyManager", e))?;

    if key.key_value.len() != subtle::X_AES_GCM_KEY_SIZE {
        return Err(format!(
            "XAesGcmKeyManager: invalid key size {} (want {})",
            key.key_value.len(),
            subtle::X_AES_GCM_KEY_SIZE
        )
        .into());
    }

    let params = key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("XAesGcmKeyManager: missing params"))?;

    validate_params(params)
}

/// Validate the given [`tink_proto::XAesGcmKeyFormat`].
fn validate_key_format(format: &tink_proto::XAesGcmKeyFormat) -> Result<(), TinkError> {
    let params = format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("XAesGcmKeyManager: missing params in key format"))?;

    validate_params(params)
}

/// Validate the given [`tink_proto::XAesGcmParams`].
fn validate_params(params: &tink_proto::XAesGcmParams) -> Result<(), TinkError> {
    let salt_size = params.salt_size as usize;
    if salt_size < subtle::X_AES_GCM_MIN_SALT_SIZE || salt_size > subtle::X_AES_GCM_MAX_SALT_SIZE {
        return Err(format!(
            "XAesGcmKeyManager: invalid salt size {} (want {}-{})",
            salt_size,
            subtle::X_AES_GCM_MIN_SALT_SIZE,
            subtle::X_AES_GCM_MAX_SALT_SIZE
        )
        .into());
    }
    Ok(())
}
