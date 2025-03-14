use anyhow::{anyhow, Result};
use image::io::Reader as ImageReader;
use quircs::Quirc;
use std::path::Path;

pub fn scan_qrcode(image_path: &str) -> Result<String> {
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