use anyhow::{anyhow, Result};
use base32::Alphabet;
use clap::{Parser, command};
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Digest};
use std::{
    collections::HashMap,
    fs::{self, File},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
    io::{self, Write, Read},
};
use rpassword::read_password;
use aes_gcm::{
    aead::{Aead, KeyInit as AeadKeyInit},
    Aes256Gcm, Nonce,
};
use url::Url;

type HmacSha1 = Hmac<Sha1>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// 服务名称
    #[arg(short = 'n', long = "name")]
    name: Option<String>,

    /// 密钥，可以是原始密钥或 otpauth:// URL
    #[arg(short = 'a', long = "secret")]
    secret: Option<String>,

    /// 设置加密密码
    #[arg(short = 'p', long = "password")]
    password: Option<String>,

    /// 验证码类型 (totp, hotp, motp)
    #[arg(short = 't', long = "type", default_value = "totp")]
    auth_type: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Secret {
    name: String,
    secret: String,
    auth_type: String,
    counter: Option<u64>, // 用于 HOTP
}

#[derive(Serialize, Deserialize)]
struct EncryptedData {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    salt: Vec<u8>,
}

fn get_config_path() -> Result<PathBuf> {
    let mut path = dirs::config_dir().ok_or_else(|| anyhow!("无法获取配置目录"))?;
    path.push("totp_cli");
    fs::create_dir_all(&path)?;
    path.push("secrets.enc");
    Ok(path)
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn encrypt_data(data: &[u8], password: &str) -> Result<EncryptedData> {
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

fn decrypt_data(encrypted: &EncryptedData, password: &str) -> Result<Vec<u8>> {
    let key = derive_key(password, &encrypted.salt);
    
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| anyhow!("解密失败，密码可能不正确"))?;
    
    Ok(plaintext)
}

fn load_secrets(password: &str) -> Result<HashMap<String, Secret>> {
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

fn save_secrets(secrets: &HashMap<String, Secret>, password: &str) -> Result<()> {
    let data = serde_json::to_vec(secrets)?;
    let encrypted = encrypt_data(&data, password)?;
    
    let path = get_config_path()?;
    let mut file = File::create(path)?;
    file.write_all(&serde_json::to_vec(&encrypted)?)?;
    
    Ok(())
}

fn parse_otpauth_url(url_str: &str) -> Result<Secret> {
    let url = Url::parse(url_str)?;
    
    if url.scheme() != "otpauth" {
        return Err(anyhow!("不是有效的 otpauth URL"));
    }
    
    let auth_type = url.host_str()
        .ok_or_else(|| anyhow!("URL 缺少验证类型"))?
        .to_string();
    
    let path = url.path().trim_start_matches('/');
    let name = path.to_string();
    
    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
    let secret = params.get("secret")
        .ok_or_else(|| anyhow!("URL 缺少 secret 参数"))?
        .to_string();
    
    let counter = if auth_type == "hotp" {
        Some(params.get("counter")
            .map(|c| c.parse::<u64>())
            .transpose()?
            .unwrap_or(0))
    } else {
        None
    };
    
    Ok(Secret {
        name,
        secret,
        auth_type,
        counter,
    })
}

fn generate_totp(secret: &str) -> Result<String> {
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

fn generate_hotp(secret: &str, counter: u64) -> Result<String> {
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

fn generate_motp(secret: &str) -> Result<String> {
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

fn generate_code(secret: &Secret) -> Result<String> {
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

fn prompt_password() -> Result<String> {
    print!("请输入密码: ");
    io::stdout().flush()?;
    Ok(read_password()?)
}

fn check_password_needed() -> bool {
    get_config_path().map(|p| p.exists()).unwrap_or(false)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // 检查是否需要设置密码
    if !check_password_needed() && cli.password.is_none() {
        println!("未找到加密数据，请使用 -p 参数设置密码");
        return Ok(());
    }
    
    // 获取密码
    let password = if let Some(pass) = cli.password {
        pass
    } else if check_password_needed() {
        prompt_password()?
    } else {
        return Ok(());
    };
    
    // 加载现有密钥
    let mut secrets = load_secrets(&password)?;
    
    // 处理添加新密钥
    if let Some(secret_str) = cli.secret {
        if secret_str.starts_with("otpauth://") {
            // 解析 otpauth URL
            let secret_info = parse_otpauth_url(&secret_str)?;
            secrets.insert(secret_info.name.clone(), secret_info.clone());
            println!("成功添加密钥：{}", secret_info.name);
        } else if let Some(name) = &cli.name {
            // 添加普通密钥
            let auth_type = cli.auth_type.clone();
            let secret = Secret {
                name: name.clone(),
                secret: secret_str,
                auth_type: auth_type.clone(),
                counter: if auth_type == "hotp" { Some(0) } else { None },
            };
            secrets.insert(name.clone(), secret);
            println!("成功添加密钥：{}", name);
        } else {
            return Err(anyhow!("添加普通密钥时必须使用 -n 参数指定服务名称"));
        }
        
        // 保存更新后的密钥
        save_secrets(&secrets, &password)?;
    } else if let Some(name) = cli.name {
        // 获取指定服务的验证码
        if let Some(secret) = secrets.get(&name) {
            let code = generate_code(secret)?;
            println!("{}: {}", name, code);
            
            // 如果是 HOTP，增加计数器
            if secret.auth_type == "hotp" {
                if let Some(counter) = secret.counter {
                    let mut updated_secret = secret.clone();
                    updated_secret.counter = Some(counter + 1);
                    secrets.insert(name, updated_secret);
                    save_secrets(&secrets, &password)?;
                }
            }
        } else {
            println!("未找到服务：{}", name);
        }
    } else {
        // 列出所有服务及其验证码
        if secrets.is_empty() {
            println!("没有保存的密钥");
        } else {
            // 收集所有需要更新的 HOTP 密钥
            let mut updates = Vec::new();
            
            for (name, secret) in &secrets {
                let code = generate_code(secret)?;
                println!("{}: {}", name, code);
                
                // 如果是 HOTP，记录需要更新的密钥
                if secret.auth_type == "hotp" {
                    if let Some(counter) = secret.counter {
                        let mut updated_secret = secret.clone();
                        updated_secret.counter = Some(counter + 1);
                        updates.push((name.clone(), updated_secret));
                    }
                }
            }
            
            // 更新 HOTP 计数器
            for (name, updated_secret) in &updates {
                secrets.insert(name.clone(), updated_secret.clone());
            }
            
            // 保存更新后的 HOTP 计数器
            if !updates.is_empty() {
                save_secrets(&secrets, &password)?;
            }
        }
    }

    Ok(())
} 
