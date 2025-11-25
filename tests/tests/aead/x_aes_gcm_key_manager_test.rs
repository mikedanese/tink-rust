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

use tink_aead::subtle;
use tink_core::{subtle::random::get_random_bytes, Aead, TinkError};
use tink_proto::prost::Message;

#[test]
fn test_x_aes_gcm_get_primitive() {
    tink_aead::init();
    let km = tink_core::registry::get_key_manager(tink_tests::X_AES_GCM_TYPE_URL)
        .expect("cannot obtain X-AES-GCM key manager");
    assert_eq!(km.type_url(), tink_tests::X_AES_GCM_TYPE_URL);
    assert_eq!(
        km.key_material_type(),
        tink_proto::key_data::KeyMaterialType::Symmetric
    );

    // Test with multiple salt sizes
    for salt_size in [8, 9, 10, 11, 12] {
        let key_format = new_x_aes_gcm_key_format(salt_size);
        let serialized_format = tink_tests::proto_encode(&key_format);
        let serialized_key = km.new_key(&serialized_format).unwrap();
        let p = km.primitive(&serialized_key).unwrap();
        let key = tink_proto::XAesGcmKey::decode(serialized_key.as_ref()).unwrap();
        validate_x_aes_gcm_primitive(p, &key).unwrap();
    }
}

#[test]
fn test_x_aes_gcm_get_primitive_with_invalid_keys() {
    tink_aead::init();
    let km = tink_core::registry::get_key_manager(tink_tests::X_AES_GCM_TYPE_URL)
        .expect("cannot obtain X-AES-GCM key manager");
    let invalid_keys = gen_invalid_x_aes_gcm_keys();
    for key in invalid_keys {
        let serialized_key = tink_tests::proto_encode(&key);
        assert!(km.primitive(&serialized_key).is_err());
    }
    assert!(km.primitive(&[]).is_err());
}

#[test]
fn test_x_aes_gcm_new_key() {
    tink_aead::init();
    let km = tink_core::registry::get_key_manager(tink_tests::X_AES_GCM_TYPE_URL)
        .expect("cannot obtain X-AES-GCM key manager");

    for salt_size in [8, 9, 10, 11, 12] {
        let key_format = new_x_aes_gcm_key_format(salt_size);
        let serialized_format = tink_tests::proto_encode(&key_format);
        let m = km.new_key(&serialized_format).unwrap();
        let key = tink_proto::XAesGcmKey::decode(m.as_ref()).unwrap();
        validate_x_aes_gcm_key(&key, salt_size).unwrap();
    }
}

#[test]
fn test_x_aes_gcm_new_key_with_invalid_format() {
    tink_aead::init();
    let km = tink_core::registry::get_key_manager(tink_tests::X_AES_GCM_TYPE_URL)
        .expect("cannot obtain X-AES-GCM key manager");

    // Invalid salt sizes
    for invalid_salt_size in [7, 13, 14] {
        let key_format = new_x_aes_gcm_key_format(invalid_salt_size);
        let serialized_format = tink_tests::proto_encode(&key_format);
        assert!(km.new_key(&serialized_format).is_err());
    }

    // Empty format
    assert!(km.new_key(&[]).is_err());
}

#[test]
fn test_x_aes_gcm_new_key_data() {
    tink_aead::init();
    let km = tink_core::registry::get_key_manager(tink_tests::X_AES_GCM_TYPE_URL)
        .expect("cannot obtain X-AES-GCM key manager");

    for salt_size in [8, 12] {
        let key_format = new_x_aes_gcm_key_format(salt_size);
        let serialized_format = tink_tests::proto_encode(&key_format);
        let kd = km.new_key_data(&serialized_format).unwrap();
        assert_eq!(kd.type_url, tink_tests::X_AES_GCM_TYPE_URL);
        assert_eq!(
            kd.key_material_type,
            tink_proto::key_data::KeyMaterialType::Symmetric as i32
        );
        let key = tink_proto::XAesGcmKey::decode(kd.value.as_ref()).unwrap();
        validate_x_aes_gcm_key(&key, salt_size).unwrap();
    }
}

#[test]
fn test_x_aes_gcm_new_key_multiple_times() {
    tink_aead::init();
    let km = tink_core::registry::get_key_manager(tink_tests::X_AES_GCM_TYPE_URL)
        .expect("cannot obtain X-AES-GCM key manager");
    let key_format = new_x_aes_gcm_key_format(12);
    let serialized_format = tink_tests::proto_encode(&key_format);

    let mut keys = std::collections::HashSet::new();
    let n_test = 26;
    for _ in 0..n_test {
        let key = km.new_key(&serialized_format).unwrap();
        keys.insert(key);
    }
    assert_eq!(keys.len(), n_test, "keys are repeated");
}

#[test]
fn test_x_aes_gcm_does_support() {
    tink_aead::init();
    let km = tink_core::registry::get_key_manager(tink_tests::X_AES_GCM_TYPE_URL)
        .expect("cannot obtain X-AES-GCM key manager");
    assert!(
        km.does_support(tink_tests::X_AES_GCM_TYPE_URL),
        "X-AES-GCM KeyManager must support {}",
        tink_tests::X_AES_GCM_TYPE_URL
    );
    assert!(
        !km.does_support("some bad type"),
        "X-AES-GCM KeyManager must only support {}",
        tink_tests::X_AES_GCM_TYPE_URL
    );
}

#[test]
fn test_x_aes_gcm_type_url() {
    tink_aead::init();
    let km = tink_core::registry::get_key_manager(tink_tests::X_AES_GCM_TYPE_URL)
        .expect("cannot obtain X-AES-GCM key manager");
    assert_eq!(km.type_url(), tink_tests::X_AES_GCM_TYPE_URL);
    assert_eq!(
        km.key_material_type(),
        tink_proto::key_data::KeyMaterialType::Symmetric
    );
    assert!(!km.supports_private_keys());
}

#[test]
fn test_x_aes_gcm_large_plaintext() {
    // Test with large plaintext like C++ (16 KiB)
    tink_aead::init();
    let key = [1u8; 32];
    let cipher = subtle::XAesGcm::new(&key, 12).unwrap();

    let plaintext = get_random_bytes(16 * 1024); // 16 KiB
    let aad = b"aad";

    let ct = cipher.encrypt(&plaintext, aad).unwrap();
    let pt = cipher.decrypt(&ct, aad).unwrap();
    assert_eq!(plaintext, pt);
}

// Helper functions
fn new_x_aes_gcm_key_format(salt_size: u32) -> tink_proto::XAesGcmKeyFormat {
    tink_proto::XAesGcmKeyFormat {
        version: tink_tests::X_AES_GCM_KEY_VERSION,
        params: Some(tink_proto::XAesGcmParams { salt_size }),
        ..Default::default()
    }
}

fn gen_invalid_x_aes_gcm_keys() -> Vec<tink_proto::XAesGcmKey> {
    vec![
        // Bad key size.
        tink_proto::XAesGcmKey {
            version: tink_tests::X_AES_GCM_KEY_VERSION,
            key_value: get_random_bytes(16),
            params: Some(tink_proto::XAesGcmParams { salt_size: 12 }),
        },
        tink_proto::XAesGcmKey {
            version: tink_tests::X_AES_GCM_KEY_VERSION,
            key_value: get_random_bytes(31),
            params: Some(tink_proto::XAesGcmParams { salt_size: 12 }),
        },
        tink_proto::XAesGcmKey {
            version: tink_tests::X_AES_GCM_KEY_VERSION,
            key_value: get_random_bytes(33),
            params: Some(tink_proto::XAesGcmParams { salt_size: 12 }),
        },
        // Bad salt size.
        tink_proto::XAesGcmKey {
            version: tink_tests::X_AES_GCM_KEY_VERSION,
            key_value: get_random_bytes(subtle::X_AES_GCM_KEY_SIZE),
            params: Some(tink_proto::XAesGcmParams { salt_size: 7 }),
        },
        tink_proto::XAesGcmKey {
            version: tink_tests::X_AES_GCM_KEY_VERSION,
            key_value: get_random_bytes(subtle::X_AES_GCM_KEY_SIZE),
            params: Some(tink_proto::XAesGcmParams { salt_size: 13 }),
        },
        // Bad version.
        tink_proto::XAesGcmKey {
            version: tink_tests::X_AES_GCM_KEY_VERSION + 1,
            key_value: get_random_bytes(subtle::X_AES_GCM_KEY_SIZE),
            params: Some(tink_proto::XAesGcmParams { salt_size: 12 }),
        },
    ]
}

fn validate_x_aes_gcm_primitive(
    p: tink_core::Primitive,
    _key: &tink_proto::XAesGcmKey,
) -> Result<(), TinkError> {
    let cipher = match p {
        tink_core::Primitive::Aead(p) => p,
        _ => return Err("key and primitive don't match".into()),
    };

    // Try to encrypt and decrypt.
    let pt = get_random_bytes(32);
    let aad = get_random_bytes(32);
    let ct = cipher.encrypt(&pt, &aad)?;
    let decrypted = cipher.decrypt(&ct, &aad)?;

    if decrypted != pt {
        return Err("decryption failed".into());
    }
    Ok(())
}

fn validate_x_aes_gcm_key(
    key: &tink_proto::XAesGcmKey,
    expected_salt_size: u32,
) -> Result<(), TinkError> {
    if key.version != tink_tests::X_AES_GCM_KEY_VERSION {
        return Err(format!(
            "incorrect key version: key_version != {}",
            tink_tests::X_AES_GCM_KEY_VERSION
        )
        .into());
    }
    if key.key_value.len() != subtle::X_AES_GCM_KEY_SIZE {
        return Err(format!(
            "incorrect key size: key_size != {}",
            subtle::X_AES_GCM_KEY_SIZE
        )
        .into());
    }
    let params = key.params.as_ref().ok_or("missing params")?;
    if params.salt_size != expected_salt_size {
        return Err(format!(
            "incorrect salt size: {} != {}",
            params.salt_size, expected_salt_size
        )
        .into());
    }

    // Try to encrypt and decrypt.
    let p = subtle::XAesGcm::new(&key.key_value, params.salt_size as usize)?;
    validate_x_aes_gcm_primitive(tink_core::Primitive::Aead(Box::new(p)), key)
}
