use anyhow::{anyhow, Result};
use base32::Alphabet;
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit;
use sha1::Sha1;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::Secret;

type HmacSha1 = Hmac<Sha1>;

pub fn generate_totp(secret: &str) -> Result<String> {
    let decoded = base32::decode(Alphabet::RFC4648 { padding: false }, secret)
        .ok_or_else(|| anyhow!("无效的 base32 编码"))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        / 30;

    let timestamp_bytes = timestamp.to_be_bytes();
    let mut mac = <HmacSha1 as KeyInit>::new_from_slice(&decoded)?;
    mac.update(&timestamp_bytes);
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0xf) as usize;
    let code = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);

    Ok(format!("{:06}", code % 1_000_000))
}

pub fn generate_hotp(secret: &str, counter: u64) -> Result<String> {
    let decoded = base32::decode(Alphabet::RFC4648 { padding: false }, secret)
        .ok_or_else(|| anyhow!("无效的 base32 编码"))?;

    let counter_bytes = counter.to_be_bytes();
    let mut mac = <HmacSha1 as KeyInit>::new_from_slice(&decoded)?;
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0xf) as usize;
    let code = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);

    Ok(format!("{:06}", code % 1_000_000))
}

pub fn generate_motp(secret: &str) -> Result<String> {
    // MOTP 实现 (Mobile OTP)
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() / 10;
    
    let time_str = format!("{:x}", time);
    
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(time_str.as_bytes());
    let result = hasher.finalize();
    
    Ok(format!("{:06x}", result[0..3].iter().fold(0, |acc, &x| (acc << 8) | x as u64)))
}

pub fn generate_code(secret: &Secret) -> Result<String> {
    match secret.auth_type.as_str() {
        "totp" => generate_totp(&secret.secret),
        "hotp" => {
            let counter = secret.counter.unwrap_or(0);
            generate_hotp(&secret.secret, counter)
        },
        "motp" => generate_motp(&secret.secret),
        _ => Err(anyhow!("不支持的验证码类型: {}", secret.auth_type)),
    }
} 