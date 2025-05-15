#![cfg_attr(windows, feature(abi_vectorcall))]

use ext_php_rs::prelude::*;
use ext_php_rs::binary::Binary;
use std::collections::HashMap;
use grammers_crypto::obfuscated::ObfuscatedCipher;

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


#[php_class(name = "AesCtr")]            // ⟵ Register AesCtr with PHP
pub struct AesCtr {
    inner: ObfuscatedCipher,
}

/// Export **this impl block** to PHP
#[php_impl]                              // ⟵ Exports methods below
impl AesCtr {
    /// __construct(string $init_bytes)
    ///
    /// @param string $init A 64-byte initialization vector
    #[php_constructor]                    // ⟵ Marks this method as PHP’s __construct
    pub fn new(init: Vec<u8>) -> PhpResult<Self> {
        let mut buf = [0u8; 64];
        buf.copy_from_slice(&init);
        Ok(AesCtr {
            inner: ObfuscatedCipher::new(&buf),
        })
    }

    /// encrypt(string $data): string
    #[php_method]                         // ⟵ Exports as an instance method
    pub fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        self.inner.encrypt(&mut data);
        data
    }

    /// decrypt(string $data): string
    #[php_method]                         // ⟵ Exports as an instance method
    pub fn decrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        self.inner.decrypt(&mut data);
        data
    }
}

#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
