use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Copy)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Totp,
    Hotp,
    Motp,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Secret {
    pub name: String,
    pub secret: String,
    pub auth_type: AuthType,
    pub counter: Option<u64>, // 用于 HOTP
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
} 