use anyhow::{anyhow, Result};
use base32::Alphabet;
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit;
use sha1::Sha1;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{Secret, AuthType};

type HmacSha1 = Hmac<Sha1>;

// 检查系统时间是否同步
fn check_time_sync() -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    
    // 检查时间是否在合理范围内（前后5分钟）
    let time_window = 5 * 60; // 5分钟
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    
    let time_diff = if current_time > now {
        current_time - now
    } else {
        now - current_time
    };
    
    if time_diff > time_window {
        return Err(anyhow!("系统时间可能不同步，请检查时间设置"));
    }
    
    Ok(())
}

// 解码base32编码的密钥
fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    base32::decode(Alphabet::RFC4648 { padding: false }, secret)
        .ok_or_else(|| anyhow!("无效的 base32 编码"))
}

// 计算OTP码
fn compute_otp_code(decoded_secret: &[u8], input_data: &[u8]) -> Result<String> {
    let mut mac = <HmacSha1 as KeyInit>::new_from_slice(decoded_secret)?;
    mac.update(input_data);
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0xf) as usize;
    let code = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);

    Ok(format!("{:06}", code % 1_000_000))
}

pub fn generate_totp(secret: &str) -> Result<String> {
    // 检查时间同步
    check_time_sync()?;
    
    let decoded = decode_secret(secret)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        / 30;

    let timestamp_bytes = timestamp.to_be_bytes();
    compute_otp_code(&decoded, &timestamp_bytes)
}

pub fn generate_hotp(secret: &str, counter: u64) -> Result<String> {
    let decoded = decode_secret(secret)?;
    let counter_bytes = counter.to_be_bytes();
    compute_otp_code(&decoded, &counter_bytes)
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
    match secret.auth_type {
        AuthType::Totp => generate_totp(&secret.secret),
        AuthType::Hotp => {
            let counter = secret.counter.unwrap_or(0);
            generate_hotp(&secret.secret, counter)
        },
        AuthType::Motp => generate_motp(&secret.secret),
    }
} 