use anyhow::{anyhow, Result};
use clap::{Parser, command};
use std::{
    collections::HashMap,
    io::{self, Write},
};
use rpassword::read_password;
use chrono::{Utc, Datelike};

use crate::{
    crypto::{load_secrets, save_secrets},
    models::{Secret, AuthType},
    otp::generate_code,
    qrcode::scan_qrcode,
    storage::get_config_path,
    utils::parse_otpauth_url,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// 服务名称
    #[arg(short = 'n', long = "name")]
    name: Option<String>,

    /// 密钥，可以是原始密钥或 otpauth:// URL
    #[arg(short = 'a', long = "secret")]
    secret: Option<String>,

    /// 设置或修改加密密码
    #[arg(short = 'p', long = "password", action = clap::ArgAction::SetTrue)]
    password: bool,

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
    
    /// 显示版本信息和ASCII艺术logo
    #[arg(short = 'v', long = "version")]
    version: bool,
}

// 密码强度验证
fn validate_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("密码不能为空".to_string());
    }
    
    if password.len() < 8 {
        return Err("密码长度必须至少为8个字符".to_string());
    }
    
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    
    if !has_uppercase || !has_lowercase || !has_digit {
        return Err("密码必须包含大小写字母和数字".to_string());
    }
    
    Ok(())
}

fn prompt_password() -> Result<String> {
    print!("请输入密码: ");
    io::stdout().flush()?;
    let password = read_password()?;
    
    if let Err(e) = validate_password(&password) {
        return Err(anyhow!("密码不符合要求: {}", e));
    }
    
    Ok(password)
}

// 要求用户输入两次密码并确保一致
fn prompt_new_password() -> Result<String> {
    print!("请输入新密码: ");
    io::stdout().flush()?;
    let password1 = read_password()?;
    
    if let Err(e) = validate_password(&password1) {
        return Err(anyhow!("密码不符合要求: {}", e));
    }
    
    print!("请再次输入新密码: ");
    io::stdout().flush()?;
    let password2 = read_password()?;
    
    if password1 != password2 {
        return Err(anyhow!("两次输入的密码不一致"));
    }
    
    Ok(password1)
}

// 初始化加密数据库 - 新增函数
fn init_encrypted_database() -> Result<String> {
    println!("未找到加密数据库，需要创建一个新的数据库。");
    
    // 先检查配置目录是否可写
    let config_path = get_config_path()?;
    match crate::utils::check_directory_writable(&config_path) {
        Ok(_) => {
            // 目录可写，继续创建数据库
            let password = prompt_new_password()?;
            
            let secrets = HashMap::new();
            
            // save_secrets 中还会再次检查，但这里的错误处理更友好
            match save_secrets(&secrets, &password) {
                Ok(_) => {
                    println!("已成功创建加密数据库！");
                    Ok(password)
                },
                Err(e) => Err(anyhow!("创建加密数据库失败: {}", e))
            }
        },
        Err(e) => Err(anyhow!("无法创建加密数据库: {}。请确保您有权限写入配置目录。", e))
    }
}

fn check_database_exists() -> bool {
    get_config_path().map(|p| p.exists()).unwrap_or(false)
}

// 显示版本信息和ASCII艺术logo
fn show_version_info() -> Result<()> {
    let package_name = env!("CARGO_PKG_NAME");
    
    let current_year = Utc::now().year();
    let copyright_years = if current_year > 2024 {
        format!("2024-{}", current_year)
    } else {
        "2024".to_string()
    };
    
    println!("
     ╭────────────────────────╮
     │   ╭───╮ ╭───╮ ╭───╮   │
     │   │ ╭─┤ │╭─╮│ │╭─╮│   │
     │   │ │ │ ││ ││ ││ ││   │
     │   │ ╰─┤ │╰─╯│ │╰─╯│   │
     │   ╰───╯ ╰───╯ ╰───╯   │
     ╰────────────────────────╯
      One-Time Password Guard
   Secure & Fast OTP Management
    -----------------------------
       © {} {} Team", copyright_years, package_name);

    // 获取版本信息
    let version = env!("CARGO_PKG_VERSION");
    let authors = env!("CARGO_PKG_AUTHORS");
    
    let binary_path = std::env::current_exe()?;
    let binary_size = if let Ok(metadata) = std::fs::metadata(&binary_path) {
        let size_kb = metadata.len() as f64 / 1024.0;
        if size_kb > 1024.0 {
            format!("{:.2} MB", size_kb / 1024.0)
        } else {
            format!("{:.2} KB", size_kb)
        }
    } else {
        "Unknown".to_string()
    };
    
    let build_date = Utc::now().format("%a %b %e %H:%M:%S %Y").to_string();

    
    println!("╭─────────────────────────────────────╮");
    println!("│ Name:         {:<24} │", package_name);
    println!("│ Version:      {:<24} │", format!("v{}", version));
    println!("│ Size:         {:<24} │", binary_size);
    println!("│ Build Date:   {:<24} │", build_date);
    println!("│ Author:       {:<24} │", authors.split(':').next().unwrap_or(format!("{} Team", package_name).as_str()));
    println!("╰─────────────────────────────────────╯");
    println!("");
    
    Ok(())
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    
    // 检查是否显示版本信息
    if cli.version {
        return show_version_info();
    }
    
    // 检查是否存在本地数据
    let has_database = check_database_exists();
    
    // 如果只是设置/修改密码但没有其他操作
    if cli.password && cli.name.is_none() && cli.secret.is_none() && cli.qrcode.is_none() && cli.rename.is_none() && cli.delete.is_none() {
        if has_database {
            // 修改现有数据库的密码
            print!("请输入原密码: ");
            io::stdout().flush()?;
            let old_password = read_password()?;
            
            // 尝试加载现有数据
            match load_secrets(&old_password) {
                Ok(secrets) => {
                    // 设置新密码
                    let new_password = prompt_new_password()?;
                    
                    // 使用新密码保存数据
                    save_secrets(&secrets, &new_password)?;
                    println!("密码已成功修改");
                },
                Err(_) => {
                    println!("原密码错误，无法修改密码");
                }
            }
        } else {
            // 创建一个空的数据库并保存
            let new_password = prompt_new_password()?;
            
            let secrets = HashMap::new();
            save_secrets(&secrets, &new_password)?;
            println!("已创建加密数据库");
        }
        return Ok(());
    }
    
    // 处理删除服务
    if let Some(service_name) = &cli.delete {
        // 如果数据库不存在，先创建
        let password = if !has_database {
            init_encrypted_database()?
        } else {
            prompt_password()?
        };
        
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
            // 如果数据库不存在，先创建
            let password = if !has_database {
                init_encrypted_database()?
            } else {
                prompt_password()?
            };
            
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
        // 如果数据库不存在，先创建
        let password = if !has_database {
            init_encrypted_database()?
        } else {
            prompt_password()?
        };
        
        // 加载现有密钥
        let mut secrets = match load_secrets(&password) {
            Ok(s) => s,
            Err(_) => {
                println!("密码错误或数据损坏");
                return Ok(());
            }
        };
        
        // 扫描二维码
        match scan_qrcode(image_path) {
            Ok(url) => {
                // 解析 otpauth URL
                match parse_otpauth_url(&url) {
                    Ok(secret_info) => {
                        // 添加密钥到数据库
                        let updated_secret = secret_info.clone();
                        secrets.insert(updated_secret.name.clone(), updated_secret);
                        save_secrets(&secrets, &password)?;
                        println!("成功从二维码添加密钥：{}", secret_info.name);
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
        // 如果数据库不存在，先创建
        let password = if !has_database {
            init_encrypted_database()?
        } else {
            prompt_password()?
        };
        
        // 加载现有密钥
        let mut secrets = match load_secrets(&password) {
            Ok(s) => s,
            Err(_) => {
                println!("密码错误或数据损坏");
                return Ok(());
            }
        };
        
        if secret_str.starts_with("otpauth://") {
            // 解析 otpauth URL
            match parse_otpauth_url(secret_str) {
                Ok(secret_info) => {
                    // 添加密钥到数据库
                    secrets.insert(secret_info.name.clone(), secret_info.clone());
                    save_secrets(&secrets, &password)?;
                    println!("成功添加密钥：{}", secret_info.name);
                },
                Err(e) => {
                    println!("解析 URL 失败: {}", e);
                }
            }
        } else if let Some(name) = &cli.name {
            // 添加普通密钥
            let auth_type = match cli.auth_type.to_lowercase().as_str() {
                "totp" => AuthType::Totp,
                "hotp" => AuthType::Hotp,
                "motp" => AuthType::Motp,
                _ => return Err(anyhow!("不支持的验证码类型: {}", cli.auth_type)),
            };
            let secret = Secret {
                name: name.clone(),
                secret: secret_str.clone(),
                auth_type: auth_type.clone(),
                counter: if auth_type == AuthType::Hotp { Some(0) } else { None },
            };
            
            // 添加密钥到数据库
            secrets.insert(name.clone(), secret.clone());
            save_secrets(&secrets, &password)?;
            println!("成功添加密钥：{}", name);
        } else {
            return Err(anyhow!("添加普通密钥时必须使用 -n 参数指定服务名称"));
        }
        
        return Ok(());
    }
    
    // 查看验证码 - 如果没有数据库，先创建
    let password = if !has_database {
        init_encrypted_database()?
    } else {
        prompt_password()?
    };
    
    // 加载现有密钥
    let mut secrets = match load_secrets(&password) {
        Ok(s) => s,
        Err(e) => {
            println!("无法加载数据: {}", e);
            return Ok(());
        }
    };
    
    // 获取指定服务的验证码
    if let Some(name) = cli.name {
        if let Some(secret) = secrets.get(&name) {
            let code = generate_code(secret)?;
            println!("{}: {}", name, code);
            
            // 如果是 HOTP，增加计数器
            if secret.auth_type == AuthType::Hotp {
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
                if secret.auth_type == AuthType::Hotp {
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