mod cli;
mod error;
mod capture;
mod forwarder;
mod protocol;
mod platform;

use clap::Parser;
use cli::{Args, Config, ForwarderConfig};
use error::Result;
use capture::{interface::InterfaceManager, packet::PacketCapture, packet::PacketFilter};
use forwarder::{base::PacketForwarder, GreForwarder};
use log::error;

#[tokio::main]
async fn main() -> Result<()> {
    // 解析命令行参数
    let args = Args::parse();
    
    // 初始化日志
    env_logger::Builder::new()
        .filter_level(args.log_level.parse().unwrap_or(log::LevelFilter::Info))
        .init();
        
    let config_path = args.config.unwrap();
    // 加载配置
    let config = Config::from_file(&config_path)?;

    // 创建接口管理器
    let interface_manager = InterfaceManager::new(&config.interface.name)?;
    
    // 设置混杂模式
    if config.interface.promiscuous {
        interface_manager.set_promiscuous(true)?;
    }
    
    // 创建通道
    let (tx, mut rx) = tokio::sync::mpsc::channel(config.forwarder.queue_size);
    
    // 创建数据包捕获器
    let mut packet_capture = PacketCapture::new(
        &interface_manager.get_interface().name,
        tx,
        PacketFilter::default(),
    )?;
    
    // 创建转发器
    let mut forwarder = create_forwarder(&config.forwarder).await?;
    
    // 初始化转发器
    forwarder.init().await?;
    
    // 启动捕获任务
    let capture_handle = tokio::spawn(async move {
        if let Err(e) = packet_capture.capture_loop().await {
            error!("Packet capture error: {}", e);
        }
    });
    
    // 启动转发任务
    let forward_handle = tokio::spawn(async move {
        while let Some(ref packet) = rx.recv().await {
            if let Err(e) = forwarder.forward_packet(packet, &config.forwarder).await {
                error!("Packet forwarding error: {}", e);
            }
        }
    });
    
    // 等待任务完成
    tokio::try_join!(capture_handle, forward_handle)?;
    
    Ok(())
}

async fn create_forwarder(config: &ForwarderConfig) -> Result<Box<dyn PacketForwarder>> {
    match config.protocol.as_str() {
        "gre" => {
            Ok(Box::new(GreForwarder::new(config).await?))
        },
        _ => Err(error::ForwarderError::Config(
            format!("Unsupported protocol: {}", config.protocol)
        ))
    }
}