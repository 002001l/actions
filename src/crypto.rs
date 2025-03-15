use anyhow::{anyhow, Result};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use argon2::{
    Algorithm, Argon2, Params, Version,
};
use std::{
    collections::HashMap,
    io::{Read, Write},
};

use crate::{
    models::{EncryptedData, Secret},
    storage::get_config_path,
    utils,
};

// 当前数据格式版本
const CURRENT_DATA_FORMAT_VERSION: u8 = 1; // 初始版本，使用Argon2加密

// 安全的内存擦除
fn secure_erase(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    // 配置Argon2参数，提供高安全性但仍保持合理的性能
    // 内存: 64MB, 迭代次数: 4, 并行度: 4
    let params = Params::new(
        64 * 1024, // 内存成本，单位为 KB (64MB)
        4,         // 迭代次数
        4,         // 并行度
        Some(32)   // 输出密钥长度
    ).map_err(|e| anyhow!("无法设置Argon2参数: {}", e))?;
    
    // 创建Argon2id实例
    let argon2 = Argon2::new(
        Algorithm::Argon2id, // 使用Argon2id变体，平衡安全性和抵抗侧信道攻击
        Version::V0x13,      // 使用最新的Argon2版本
        params
    );
    
    // 派生密钥
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("密钥派生失败: {}", e))?;
    
    Ok(key)
}

pub fn encrypt_data(data: &[u8], password: &str) -> Result<EncryptedData> {
    let salt = rand::random::<[u8; 16]>().to_vec();
    let mut key = derive_key(password, &salt)?;
    
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // 添加版本标记到数据
    let mut versioned_data = Vec::with_capacity(data.len() + 1);
    versioned_data.push(CURRENT_DATA_FORMAT_VERSION);
    versioned_data.extend_from_slice(data);
    
    // 添加关联数据，以提高安全性
    // 这里我们使用salt作为关联数据，增加额外的完整性保护
    let payload = Payload {
        msg: &versioned_data,
        aad: &salt,
    };
    
    let ciphertext = cipher.encrypt(nonce, payload)
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
    let mut key = derive_key(password, &encrypted.salt)?;
    
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    // 使用与加密相同的关联数据
    let payload = Payload {
        msg: &encrypted.ciphertext,
        aad: &encrypted.salt,
    };
    
    let plaintext = cipher.decrypt(nonce, payload)
        .map_err(|_| anyhow!("解密失败，密码可能不正确或数据已被篡改"))?;
    
    // 安全擦除密钥
    secure_erase(&mut key);
    
    // 检查版本并移除版本标记
    if plaintext.is_empty() {
        return Err(anyhow!("解密后的数据为空"));
    }
    
    let version = plaintext[0];
    // 检查版本是否支持
    if version != CURRENT_DATA_FORMAT_VERSION {
        return Err(anyhow!("不支持的数据格式版本。请升级到最新版本。"));
    }
    
    // 移除版本标记
    Ok(plaintext[1..].to_vec())
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
    
    // 检查目录是否可写
    utils::check_directory_writable(&path)?;
    
    // 使用文件锁打开文件（写入模式）
    let mut file = utils::open_file_with_lock(&path, true)?;
    file.write_all(&serde_json::to_vec(&encrypted)?)?;
    
    // 设置严格的文件权限
    utils::set_file_permissions(&path)?;
    
    Ok(())
} 