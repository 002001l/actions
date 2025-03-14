use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Secret {
    pub name: String,
    pub secret: String,
    pub auth_type: String,
    pub counter: Option<u64>, // 用于 HOTP
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
} 