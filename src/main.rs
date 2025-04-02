mod cli;
mod error;
mod capture;
mod forwarder;
mod protocol;
mod platform;

use clap::Parser;
use num_cpus;
use cli::{Args, Config, ForwarderConfig};
use error::Result;
use capture::{interface::InterfaceManager, packet::PacketCapture, packet::PacketFilter};
use forwarder::{base::PacketForwarder, GreForwarder};
use log::error;
use tokio::sync::broadcast;
use std::sync::Arc;

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
    
    // 使用 broadcast channel 替代 mpsc
    let (tx, _) = broadcast::channel(config.forwarder.queue_size * 2);
    let packet_tx = tx.clone();
    
    // 创建数据包捕获器
    let mut packet_capture = PacketCapture::new(
        &interface_manager.get_interface().name,
        packet_tx,
        PacketFilter::default(),
    )?;
    
    // 将配置包装在 Arc 中以便共享
    let forwarder_config = Arc::new(config.forwarder);
    
    // 使用固定的线程数
    let worker_threads = num_cpus::get();
    let mut forward_handles = Vec::new();
    for _ in 0..worker_threads {
        let mut forwarder = create_forwarder(&forwarder_config).await?;
        let mut rx = tx.subscribe();
        let config = Arc::clone(&forwarder_config);
        forward_handles.push(tokio::spawn(async move {
            while let Ok(packet) = rx.recv().await {
                if let Err(e) = forwarder.forward_packet(&packet, &config).await {
                    error!("Forwarding error: {}", e);
                }
            }
        }));
    }
    
    // 启动捕获任务
    let capture_handle = tokio::spawn(async move {
        if let Err(e) = packet_capture.capture_loop().await {
            error!("Packet capture error: {}", e);
        }
    });
    
    // 等待所有任务完成
    let forward_results = futures::future::join_all(forward_handles).await;
    capture_handle.await?;
    
    // 检查转发任务的结果
    for result in forward_results {
        if let Err(e) = result {
            error!("Forwarding task error: {}", e);
        }
    }
    
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