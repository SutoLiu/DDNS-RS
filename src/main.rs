use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use ddns_rs::{auth, config, engine, server};

#[derive(Parser)]
#[command(name = "ddns-rs", version, about = "轻量动态域名解析服务")]
struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long = "config", default_value = "./config.json")]
    config: PathBuf,
    /// 重置登录密码（至少 8 位）
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    reset_password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    if let Some(pwd) = cli.reset_password.as_deref() {
        auth::check_strength(pwd)?;
        config::Config::reset_pwd_hash(&cli.config, &auth::pwd_hash(pwd)?).await?;
        println!("密码已重置");
        return Ok(());
    }

    let mut cfg = config::Config::load(&cli.config).await?;
    if cfg.pwd_hash.is_empty() {
        tracing::info!("尚未设置密码，请在浏览器中完成首次初始化");
    }
    if let Err(e) = cfg.validate() {
        tracing::warn!("配置校验未通过: {e}");
    }

    let cfg_store = Arc::new(config::ConfigStore::new(cfg, cli.config.clone()));
    let engine = engine::Engine::new(cfg_store.clone());
    tokio::spawn(engine.clone().run());
    server::serve(cfg_store, engine).await?;
    Ok(())
}
