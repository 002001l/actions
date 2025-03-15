use anyhow::{anyhow, Result};
use std::{
    fs::{self},
    path::PathBuf,
};

use crate::crypto::load_secrets;

pub fn get_config_path() -> Result<PathBuf> {
    // 使用编译时常量获取package名称
    let package_name = env!("CARGO_PKG_NAME");
    let mut path = dirs::config_dir().ok_or_else(|| anyhow!("无法获取配置目录"))?;
    path.push(format!("{}.enc", package_name));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(path)
}

pub fn is_empty_password() -> Result<bool> {
    if !get_config_path().map(|p| p.exists()).unwrap_or(false) {
        return Ok(false); // 没有本地数据
    }
    
    // 尝试用空密码加载数据
    match load_secrets("") {
        Ok(_) => Ok(true),  // 成功加载，说明是空密码
        Err(_) => Ok(false) // 加载失败，说明不是空密码
    }
} 