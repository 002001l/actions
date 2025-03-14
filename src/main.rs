mod cli;
mod crypto;
mod models;
mod otp;
mod qrcode;
mod storage;
mod utils;

fn main() -> anyhow::Result<()> {
    cli::run()
} 