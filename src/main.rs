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
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
    io::{self, Write, Read},
};
use rpassword::read_password;
use aes_gcm::{
    aead::Aead,
    Aes256Gcm, Nonce,
};
use url::Url;
use image::io::Reader as ImageReader;
use quircs::Quirc;

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
    
    /// 二维码图片路径 (.jpg/.jpeg/.png)
    #[arg(short = 'j', long = "qrcode")]
    qrcode: Option<String>,
    
    /// 重命名服务
    #[arg(short = 'r', long = "rename")]
    rename: Option<String>,
    
    /// 重命名的新名称 (与 -r 一起使用)
    #[arg(short = 'N', long = "new-name")]
    new_name: Option<String>,
    
    /// 删除指定服务
    #[arg(short = 'd', long = "delete")]
    delete: Option<String>,
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

fn scan_qrcode(image_path: &str) -> Result<String> {
    // 检查文件扩展名
    let path = Path::new(image_path);
    let extension = path.extension()
        .and_then(|ext| ext.to_str())
        .ok_or_else(|| anyhow!("无法获取文件扩展名"))?
        .to_lowercase();
    
    if !["jpg", "jpeg", "png"].contains(&extension.as_str()) {
        return Err(anyhow!("不支持的图片格式，仅支持 .jpg/.jpeg/.png"));
    }
    
    // 读取图片
    let img = ImageReader::open(image_path)?
        .decode()?
        .to_luma8();
    
    // 扫描二维码
    let mut quirc = Quirc::new();
    let codes = quirc.identify(img.width() as usize, img.height() as usize, &img);
    
    for code in codes {
        let code = code?;
        if let Ok(decoded) = code.decode() {
            if let Ok(text) = String::from_utf8(decoded.payload) {
                if text.starts_with("otpauth://") {
                    return Ok(text);
                }
            }
        }
    }
    
    Err(anyhow!("未在图片中找到有效的 otpauth:// 二维码"))
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

// 检查是否使用空密码
fn is_empty_password() -> Result<bool> {
    if !check_password_needed() {
        return Ok(false); // 没有本地数据
    }
    
    // 尝试用空密码加载数据
    match load_secrets("") {
        Ok(_) => Ok(true),  // 成功加载，说明是空密码
        Err(_) => Ok(false) // 加载失败，说明不是空密码
    }
}

// 获取有效密码（考虑空密码情况）
fn get_effective_password(cli_password: Option<&String>) -> Result<String> {
    // 检查是否是空密码
    if is_empty_password()? {
        return Ok("".to_string());
    }
    
    // 不是空密码，需要用户提供
    if let Some(pass) = cli_password {
        Ok(pass.clone())
    } else {
        prompt_password()
    }
}

// 添加服务时使用的特殊函数，不需要密码
fn add_service_without_password(secret: Secret) -> Result<()> {
    // 检查是否有本地数据
    let config_path = get_config_path()?;
    if !config_path.exists() {
        return Err(anyhow!("未找到加密数据，请先使用 -p 参数设置密码"));
    }
    
    // 尝试使用空密码
    if let Ok(mut secrets) = load_secrets("") {
        secrets.insert(secret.name.clone(), secret);
        save_secrets(&secrets, "")?;
        return Ok(());
    }
    
    // 如果空密码不行，需要读取加密的数据但不解密
    let mut file = File::open(config_path)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;
    
    // 验证数据格式是否正确，但不使用解密后的结果
    let _: EncryptedData = serde_json::from_slice(&encrypted_data)?;
    
    // 创建一个临时文件来存储新的服务
    let temp_path = dirs::config_dir().unwrap().join("totp_cli").join("temp_service.json");
    let mut temp_file = File::create(&temp_path)?;
    serde_json::to_writer_pretty(&mut temp_file, &secret)?;
    
    println!("服务 \"{}\" 已添加到临时文件。下次查看验证码时将自动合并。", secret.name);
    println!("临时文件路径: {}", temp_path.display());
    
    Ok(())
}

// 合并临时添加的服务
fn merge_temp_services(secrets: &mut HashMap<String, Secret>) -> Result<bool> {
    let temp_path = dirs::config_dir().unwrap().join("totp_cli").join("temp_service.json");
    if !temp_path.exists() {
        return Ok(false);
    }
    
    let temp_file = File::open(&temp_path)?;
    let temp_service: Secret = serde_json::from_reader(temp_file)?;
    
    secrets.insert(temp_service.name.clone(), temp_service.clone());
    println!("已合并临时添加的服务: {}", temp_service.name);
    
    // 删除临时文件
    fs::remove_file(temp_path)?;
    
    Ok(true)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 检查是否存在本地数据
    let has_local_data = check_password_needed();
    let is_empty_pass = is_empty_password()?;
    
    // 处理删除服务
    if let Some(service_name) = &cli.delete {
        if !has_local_data {
            println!("未找到加密数据，请先使用 -p 参数设置密码");
            return Ok(());
        }
        
        // 获取密码（考虑空密码情况）
        let password = get_effective_password(cli.password.as_ref())?;
        
        // 加载现有密钥
        let mut secrets = match load_secrets(&password) {
            Ok(s) => s,
            Err(_) => {
                println!("密码错误或数据损坏");
                return Ok(());
            }
        };
        
        // 删除服务
        if secrets.remove(service_name).is_some() {
            save_secrets(&secrets, &password)?;
            println!("已删除服务：{}", service_name);
        } else {
            println!("未找到服务：{}", service_name);
        }
        
        return Ok(());
    }
    
    // 处理重命名服务
    if let Some(old_name) = &cli.rename {
        if let Some(new_name) = &cli.new_name {
            if !has_local_data {
                println!("未找到加密数据，请先使用 -p 参数设置密码");
                return Ok(());
            }
            
            // 获取密码（考虑空密码情况）
            let password = get_effective_password(cli.password.as_ref())?;
            
            // 加载现有密钥
            let mut secrets = match load_secrets(&password) {
                Ok(s) => s,
                Err(_) => {
                    println!("密码错误或数据损坏");
                    return Ok(());
                }
            };
            
            // 查找并重命名服务
            if let Some(secret) = secrets.remove(old_name) {
                let mut updated_secret = secret.clone();
                updated_secret.name = new_name.clone();
                secrets.insert(new_name.clone(), updated_secret);
                save_secrets(&secrets, &password)?;
                println!("已将服务 \"{}\" 重命名为 \"{}\"", old_name, new_name);
            } else {
                println!("未找到服务：{}", old_name);
            }
            
            return Ok(());
        } else {
            println!("重命名服务时必须使用 -N 参数指定新名称");
            return Ok(());
        }
    }
    
    // 处理二维码扫描
    if let Some(image_path) = &cli.qrcode {
        // 如果没有本地数据，必须先设置密码
        if !has_local_data {
            if cli.password.is_none() {
                println!("未找到加密数据，请使用 -p 参数设置密码");
                return Ok(());
            }
            
            // 创建一个空的数据库并保存
            let password = cli.password.as_ref().unwrap();
            let secrets = HashMap::new();
            save_secrets(&secrets, password)?;
            println!("已创建加密数据库");
        }
        
        // 扫描二维码
        match scan_qrcode(image_path) {
            Ok(url) => {
                // 解析 otpauth URL
                match parse_otpauth_url(&url) {
                    Ok(secret_info) => {
                        // 添加服务不需要密码
                        if let Err(e) = add_service_without_password(secret_info.clone()) {
                            println!("添加服务失败: {}", e);
                        } else {
                            println!("成功从二维码添加密钥：{}", secret_info.name);
                        }
                    },
                    Err(e) => {
                        println!("解析二维码内容失败: {}", e);
                    }
                }
            },
            Err(e) => {
                println!("扫描二维码失败: {}", e);
            }
        }
        
        return Ok(());
    }
    
    // 处理添加新密钥的情况
    if let Some(secret_str) = &cli.secret {
        // 如果没有本地数据，必须先设置密码
        if !has_local_data {
            if cli.password.is_none() {
                println!("未找到加密数据，请使用 -p 参数设置密码");
                return Ok(());
            }
            
            // 创建一个空的数据库并保存
            let password = cli.password.as_ref().unwrap();
            let secrets = HashMap::new();
            save_secrets(&secrets, password)?;
            println!("已创建加密数据库");
        }
        
        if secret_str.starts_with("otpauth://") {
            // 解析 otpauth URL
            match parse_otpauth_url(secret_str) {
                Ok(secret_info) => {
                    // 添加服务不需要密码
                    if let Err(e) = add_service_without_password(secret_info.clone()) {
                        println!("添加服务失败: {}", e);
                    } else {
                        println!("成功添加密钥：{}", secret_info.name);
                    }
                },
                Err(e) => {
                    println!("解析 URL 失败: {}", e);
                }
            }
        } else if let Some(name) = &cli.name {
            // 添加普通密钥
            let auth_type = cli.auth_type.clone();
            let secret = Secret {
                name: name.clone(),
                secret: secret_str.clone(),
                auth_type: auth_type.clone(),
                counter: if auth_type == "hotp" { Some(0) } else { None },
            };
            
            // 添加服务不需要密码
            if let Err(e) = add_service_without_password(secret.clone()) {
                println!("添加服务失败: {}", e);
            } else {
            println!("成功添加密钥：{}", name);
        }
        } else {
            return Err(anyhow!("添加普通密钥时必须使用 -n 参数指定服务名称"));
        }
        
        return Ok(());
    }
    
    // 如果只是设置/修改密码但没有其他操作
    if cli.password.is_some() && cli.name.is_none() && cli.secret.is_none() && cli.qrcode.is_none() && cli.rename.is_none() && cli.delete.is_none() {
        let new_password = cli.password.as_ref().unwrap();
        
        if has_local_data {
            // 修改现有数据库的密码
            if is_empty_pass {
                // 如果当前是空密码，直接修改
                let secrets = load_secrets("")?;
                save_secrets(&secrets, new_password)?;
                println!("密码已成功修改");
            } else {
                // 如果当前不是空密码，需要输入原密码
                print!("请输入原密码: ");
                io::stdout().flush()?;
                let old_password = read_password()?;
                
                // 尝试加载现有数据
                match load_secrets(&old_password) {
                    Ok(secrets) => {
                        // 使用新密码保存数据
                        save_secrets(&secrets, new_password)?;
                        println!("密码已成功修改");
                    },
                    Err(_) => {
                        println!("原密码错误，无法修改密码");
                    }
                }
            }
        } else {
            // 创建一个空的数据库并保存
            let secrets = HashMap::new();
            save_secrets(&secrets, new_password)?;
            println!("已创建加密数据库");
        }
        return Ok(());
    }
    
    // 查看验证码时需要密码
    if !has_local_data {
        println!("未找到加密数据，请使用 -p 参数设置密码");
        return Ok(());
    }
    
    // 获取密码用于查看验证码（考虑空密码情况）
    let password = get_effective_password(cli.password.as_ref())?;
    
    // 加载现有密钥
    let mut secrets = match load_secrets(&password) {
        Ok(s) => s,
        Err(e) => {
            println!("无法加载数据: {}", e);
            return Ok(());
        }
    };
    
    // 合并临时添加的服务
    let merged = merge_temp_services(&mut secrets)?;
    if merged {
        // 如果有合并的服务，保存更新后的数据
        save_secrets(&secrets, &password)?;
    }
    
    // 获取指定服务的验证码
    if let Some(name) = cli.name {
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