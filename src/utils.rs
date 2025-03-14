use anyhow::{anyhow, Result};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
};
use url::Url;

use crate::{
    crypto::{load_secrets, save_secrets},
    models::{EncryptedData, Secret},
    storage::get_config_path,
};

pub fn parse_otpauth_url(url_str: &str) -> Result<Secret> {
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

// 添加服务时使用的特殊函数，不需要密码
pub fn add_service_without_password(secret: Secret) -> Result<()> {
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
pub fn merge_temp_services(secrets: &mut HashMap<String, Secret>) -> Result<bool> {
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