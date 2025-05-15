#![cfg_attr(windows, feature(abi_vectorcall))]

use ext_php_rs::prelude::*;
use ext_php_rs::binary::Binary;
use std::collections::HashMap;

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


#[php_function]
pub fn tg_new_ctr(init: Vec<u8>) -> PhpResult<ResourceId> {
    if init.len() != 64 {
        return Err(PhpError::InvalidArgument("init must be 64 bytes".into()));
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&init);
    let cipher = grammers_crypto::ObfuscatedCipher::new(&buf);
    let rid = flags::DataType::Resource::builder().build(cipher)?;
    Ok(rid)
}

#[php_function]
pub fn tg_encrypt_ctr(rid: ResourceId, mut data: Vec<u8>) -> PhpResult<Vec<u8>> {
    let mut cipher: &mut ObfuscatedCipher = flags::DataType::Resource::get_mut(rid)?;
    cipher.encrypt(&mut data);
    Ok(data)
}

#[php_function]
pub fn tg_decrypt_ctr(rid: ResourceId, mut data: Vec<u8>) -> PhpResult<Vec<u8>> {
    let mut cipher: &mut ObfuscatedCipher = flags::DataType::Resource::get_mut(rid)?;
    cipher.decrypt(&mut data);
    Ok(data)
}

#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
