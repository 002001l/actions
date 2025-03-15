use anyhow::{anyhow, Result};
use std::{
    fs::{self},
    path::PathBuf,
};

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