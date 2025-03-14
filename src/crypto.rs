use anyhow::{anyhow, Result};
use aes_gcm::{
    aead::Aead,
    Aes256Gcm, KeyInit, Nonce,
};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use std::{
    collections::HashMap,
    io::{Read, Write},
};

use crate::{
    models::{EncryptedData, Secret},
    storage::get_config_path,
    utils,
};

// 安全的内存擦除
fn secure_erase(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
}

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    // 使用 PBKDF2 进行密钥派生
    pbkdf2_hmac_array::<Sha256, 32>(
        password.as_bytes(),
        salt,
        100_000, // 迭代次数
    )
}

pub fn encrypt_data(data: &[u8], password: &str) -> Result<EncryptedData> {
    let salt = rand::random::<[u8; 16]>().to_vec();
    let mut key = derive_key(password, &salt);
    
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|_| anyhow!("加密失败"))?;
    
    // 安全擦除密钥
    secure_erase(&mut key);
    
    Ok(EncryptedData {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        salt,
    })
}

pub fn decrypt_data(encrypted: &EncryptedData, password: &str) -> Result<Vec<u8>> {
    let mut key = derive_key(password, &encrypted.salt);
    
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| anyhow!("解密失败，密码可能不正确"))?;
    
    // 安全擦除密钥
    secure_erase(&mut key);
    
    Ok(plaintext)
}

pub fn load_secrets(password: &str) -> Result<HashMap<String, Secret>> {
    let path = get_config_path()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    
    // 使用文件锁打开文件（读取模式）
    let mut file = utils::open_file_with_lock(&path, false)?;
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
    // 使用文件锁打开文件（写入模式）
    let mut file = utils::open_file_with_lock(&path, true)?;
    file.write_all(&serde_json::to_vec(&encrypted)?)?;
    
    // 设置严格的文件权限
    utils::set_file_permissions(&path)?;
    
    Ok(())
} 