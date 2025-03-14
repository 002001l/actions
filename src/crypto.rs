use anyhow::{anyhow, Result};
use aes_gcm::{
    aead::Aead,
    Aes256Gcm, KeyInit, Nonce,
};
use sha2::{Sha256, Digest};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
};

use crate::{
    models::{EncryptedData, Secret},
    storage::get_config_path,
};

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

pub fn encrypt_data(data: &[u8], password: &str) -> Result<EncryptedData> {
    let salt = rand::random::<[u8; 16]>().to_vec();
    let key = derive_key(password, &salt);
    
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|_| anyhow!("加密失败"))?;
    
    Ok(EncryptedData {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        salt,
    })
}

pub fn decrypt_data(encrypted: &EncryptedData, password: &str) -> Result<Vec<u8>> {
    let key = derive_key(password, &encrypted.salt);
    
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| anyhow!("解密失败，密码可能不正确"))?;
    
    Ok(plaintext)
}

pub fn load_secrets(password: &str) -> Result<HashMap<String, Secret>> {
    let path = get_config_path()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    
    let mut file = File::open(path)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;
    
    let encrypted: EncryptedData = serde_json::from_slice(&encrypted_data)?;
    let decrypted = decrypt_data(&encrypted, password)?;
    
    Ok(serde_json::from_slice(&decrypted)?)
}

pub fn save_secrets(secrets: &HashMap<String, Secret>, password: &str) -> Result<()> {
    let data = serde_json::to_vec(secrets)?;
    let encrypted = encrypt_data(&data, password)?;
    
    let path = get_config_path()?;
    let mut file = File::create(path)?;
    file.write_all(&serde_json::to_vec(&encrypted)?)?;
    
    Ok(())
} 