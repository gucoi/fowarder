//! 数据包捕获模块
//! 
//! 该模块提供了网络接口管理和数据包捕获的功能。

pub mod interface;
pub mod packet;

pub use interface::InterfaceManager;
use packet::PacketFilter;
pub use packet::{PacketCapture, PacketInfo};

use crate::error::Result;
use pnet::datalink::NetworkInterface;
use tokio::sync::broadcast;

/// 捕获配置
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// 接口名称
    pub interface_name: String,
    /// 是否开启混杂模式
    pub promiscuous: bool,
    /// 捕获缓冲区大小(字节)
    pub buffer_size: usize,
    /// 数据包通道容量
    pub channel_capacity: usize,
    /// 最大包大小
    pub max_packet_size: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface_name: String::new(),
            promiscuous: false,
            buffer_size: 65536,
            channel_capacity: 1000,
            max_packet_size: 65536,
        }
    }
}

/// 捕获管理器
pub struct CaptureManager {
    config: CaptureConfig,
    interface_manager: InterfaceManager,
    packet_capture: Option<PacketCapture>,
}

impl CaptureManager {
    /// 创建新的捕获管理器
    pub fn new(config: CaptureConfig) -> Result<Self> {
        let interface_manager = InterfaceManager::new(&config.interface_name)?;
        
        Ok(Self {
            config,
            interface_manager,
            packet_capture: None,
        })
    }

    /// 启动数据包捕获
    pub async fn start_capture(&mut self) -> Result<broadcast::Receiver<PacketInfo>> {
        // 设置混杂模式
        if self.config.promiscuous {
            self.interface_manager.set_promiscuous(true)?;
        }

        // 创建广播通道
        let (tx, rx) = broadcast::channel(self.config.channel_capacity);

        // 创建数据包捕获器
        let packet_capture = PacketCapture::new(
            &self.interface_manager.get_interface().name,
            tx,
            PacketFilter::default(), 
        )?;

        self.packet_capture = Some(packet_capture);
        Ok(rx)
    }

    /// 停止数据包捕获
    pub async fn stop_capture(&mut self) {
        self.packet_capture = None;
    }

    /// 获取当前接口
    pub fn get_interface(&self) -> &NetworkInterface {
        self.interface_manager.get_interface()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_config_default() {
        let config = CaptureConfig::default();
        assert_eq!(config.interface_name, "");
        assert_eq!(config.promiscuous, false);
        assert_eq!(config.buffer_size, 65536);
    }

    #[tokio::test]
    async fn test_capture_manager() {
        let config = CaptureConfig {
            interface_name: "lo".to_string(), // 使用本地回环接口进行测试
            ..Default::default()
        };

        let mut manager = CaptureManager::new(config).unwrap();
        let mut rx = manager.start_capture().await.unwrap();

        // 简单测试接收
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            rx.recv()
        ).await.ok();

        manager.stop_capture().await;
    }
}