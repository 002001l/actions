use anyhow::{anyhow, Result};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::Mutex,
};
use url::Url;
use std::sync::Arc;

use crate::{
    crypto::{load_secrets, save_secrets},
    models::{EncryptedData, Secret},
    storage::get_config_path,
};

// 全局临时服务存储
lazy_static::lazy_static! {
    static ref TEMP_SERVICES: Arc<Mutex<HashMap<String, Secret>>> = Arc::new(Mutex::new(HashMap::new()));
}

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
        secrets.insert(secret.name.clone(), secret.clone());
        save_secrets(&secrets, "")?;
        return Ok(());
    }
    
    // 如果空密码不行，将服务添加到内存中的临时存储
    let mut temp_services = TEMP_SERVICES.lock().map_err(|_| anyhow!("无法获取临时服务锁"))?;
    temp_services.insert(secret.name.clone(), secret);
    
    println!("服务 \"{}\" 已添加到临时存储。下次查看验证码时将自动合并。", secret.name);
    
    Ok(())
}

// 合并临时添加的服务
pub fn merge_temp_services(secrets: &mut HashMap<String, Secret>) -> Result<bool> {
    let mut temp_services = TEMP_SERVICES.lock().map_err(|_| anyhow!("无法获取临时服务锁"))?;
    if temp_services.is_empty() {
        return Ok(false);
    }
    
    // 合并所有临时服务
    for (name, secret) in temp_services.drain() {
        secrets.insert(name.clone(), secret.clone());
        println!("已合并临时添加的服务: {}", name);
    }
    
    Ok(true)
}

// 设置文件权限
fn set_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600); // 只允许所有者读写
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

// 打开文件时获取文件锁
fn open_file_with_lock(path: &Path, write: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(!write)
        .write(write)
        .create(write)
        .open(path)?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        file.set_cloexec(true)?;
    }
    
    Ok(file)
} 