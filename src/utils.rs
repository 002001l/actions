use anyhow::{anyhow, Result};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    path::Path,
    io::Write,
};
use url::Url;
#[cfg(unix)]
use libc;

use crate::{
    models::{Secret, AuthType},
    storage::get_config_path,
};

// 检查目录是否可写
pub fn check_directory_writable(path: &Path) -> Result<()> {
    // 如果目录不存在，尝试创建它
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
        
        // 创建一个临时文件来测试写入权限
        let test_file_path = parent.join(".write_test_file");
        let file_result = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&test_file_path);
            
        match file_result {
            Ok(mut file) => {
                // 尝试写入一些数据
                let write_result = file.write_all(b"test");
                
                // 无论成功与否，尝试删除测试文件
                let _ = fs::remove_file(&test_file_path);
                
                // 检查写入是否成功
                write_result.map_err(|e| anyhow!("目录不可写: {}", e))?;
                Ok(())
            },
            Err(e) => Err(anyhow!("目录不可写: {}", e)),
        }
    } else {
        Err(anyhow!("无法获取父目录"))
    }
}

pub fn parse_otpauth_url(url_str: &str) -> Result<Secret> {
    let url = Url::parse(url_str)?;
    
    if url.scheme() != "otpauth" {
        return Err(anyhow!("不是有效的 otpauth URL"));
    }
    
    let auth_type_str = url.host_str()
        .ok_or_else(|| anyhow!("URL 缺少验证类型"))?
        .to_string();
        
    // 严格检查验证类型，不允许任何不标准的类型名称
    let auth_type = match auth_type_str.to_lowercase().as_str() {
        "totp" => AuthType::Totp,
        "hotp" => AuthType::Hotp,
        "motp" => AuthType::Motp,
        _ => return Err(anyhow!("不支持的验证类型: {}", auth_type_str)),
    };
    
    let path = url.path().trim_start_matches('/');
    if path.is_empty() {
        return Err(anyhow!("URL 缺少服务名称"));
    }
    
    let name = path.to_string();
    
    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
    let secret = params.get("secret")
        .ok_or_else(|| anyhow!("URL 缺少 secret 参数"))?
        .to_string();
    
    // 严格检查必要参数
    if secret.is_empty() {
        return Err(anyhow!("密钥不能为空"));
    }
    
    let counter = if auth_type == AuthType::Hotp {
        // HOTP必须有counter参数
        Some(params.get("counter")
            .ok_or_else(|| anyhow!("HOTP URL 缺少 counter 参数"))?
            .parse::<u64>()
            .map_err(|_| anyhow!("counter 参数必须是有效的数字"))?
        )
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

// 设置文件权限
pub fn set_file_permissions(path: &Path) -> Result<()> {
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
pub fn open_file_with_lock(path: &Path, write: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(!write)
        .write(write)
        .create(write)
        .open(path)?;
    
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        
        // 设置文件描述符标志
        unsafe {
            libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
        }
        
        // 添加文件锁，避免多实例并发修改
        let lock_type = if write {
            libc::LOCK_EX // 独占锁
        } else {
            libc::LOCK_SH // 共享锁
        };
        
        // 尝试获取锁，不阻塞
        if unsafe { libc::flock(file.as_raw_fd(), lock_type | libc::LOCK_NB) } != 0 {
            return Err(anyhow!("无法获取文件锁，可能有其他实例正在访问该文件"));
        }
    }
    
    Ok(file)
} 