use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Copy)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Totp,
    Hotp,
    Motp,
}

impl AuthType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "totp" => Ok(AuthType::Totp),
            "hotp" => Ok(AuthType::Hotp),
            "motp" => Ok(AuthType::Motp),
            _ => Err(format!("不支持的验证码类型: {}", s)),
        }
    }
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