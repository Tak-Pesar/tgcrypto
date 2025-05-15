#![cfg_attr(windows, feature(abi_vectorcall))]

use ext_php_rs::prelude::*;
use ext_php_rs::binary::Binary;
use std::collections::HashMap;
use aes::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray};

#[php_const]
pub const TGCRYPTO_VERSION: &str = "0.0.1";

#[php_function]
pub fn tg_factorize(pq: u64) -> HashMap<&'static str, u64> {
    let (p,q) = grammers_crypto::factorize::factorize(pq);
    let mut result = HashMap::new();
    result.insert("p",p);
    result.insert("q",q);
    result
}

#[php_function]
pub fn tg_encrypt_ige(plain: String, key: Binary<u8>, iv: Binary<u8>) -> Result<String, String> {
    let plain_bytes = plain.as_bytes();

    let key_bytes = key.as_ref();
    let iv_bytes = iv.as_ref();

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes);
    
    let mut iv_array = [0u8; 32];
    iv_array.copy_from_slice(iv_bytes);

    let cipher = grammers_crypto::encrypt_ige(plain_bytes, &key_array, &iv_array);

    Ok(grammers_crypto::hex::to_hex(&cipher))
}

#[php_function]
pub fn tg_decrypt_ige(cipher: Binary<u8>, key: Binary<u8>, iv: Binary<u8>) -> Result<String, String> {
    let cipher_bytes = cipher.as_ref();

    let key_bytes = key.as_ref();
    let iv_bytes = iv.as_ref();

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes);
    
    let mut iv_array = [0u8; 32];
    iv_array.copy_from_slice(iv_bytes);

    let plain = grammers_crypto::decrypt_ige(cipher_bytes, &key_array, &iv_array);

    Ok(grammers_crypto::hex::to_hex(&plain))
}

#[php_class(name = "ObfuscatedCipher")]
pub struct ObfuscatedCipher {
    rx: ctr::Ctr128BE<aes::Aes256>,
    tx: ctr::Ctr128BE<aes::Aes256>,
}

#[php_impl]
impl ObfuscatedCipher {
    #[php_constructor]
    pub fn new(init: &[u8; 64]) -> PhpResult<Self> {
        let init_rev = init.iter().copied().rev().collect::<Vec<_>>();
        Self {
            rx: ctr::Ctr128BE::<aes::Aes256>::new(
                GenericArray::from_slice(&init_rev[8..40]),
                GenericArray::from_slice(&init_rev[40..56]),
            ),
            tx: ctr::Ctr128BE::<aes::Aes256>::new(
                GenericArray::from_slice(&init[8..40]),
                GenericArray::from_slice(&init[40..56]),
            ),
        }
    }
    #[php_method]
    pub fn encrypt(&mut self, buffer: &mut [u8]) -> Vec<u8> {
        self.tx.apply_keystream(buffer);
    }
    #[php_method]
    pub fn decrypt(&mut self, buffer: &mut [u8]) -> Vec<u8> {
        self.rx.apply_keystream(buffer);
    }
}

#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
