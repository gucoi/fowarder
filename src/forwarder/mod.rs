//! 数据包转发模块
//! 
//! 该模块提供了各种协议的数据包转发实现。

pub mod base;
pub mod gre;
pub mod socket;
pub mod vxlan;
pub mod zmq;
pub mod state;

pub use base::PacketForwarder;
pub use gre::GreForwarder;
pub use vxlan::VxlanForwarder;

use crate::error::Result;
use crate::cli::ForwarderConfig;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 转发器工厂
pub struct ForwarderFactory;

impl ForwarderFactory {
    /// 创建新的转发器实例
    pub async fn create(config: ForwarderConfig) -> Result<Arc<Mutex<dyn PacketForwarder>>> {
        let forwarder: Arc<Mutex<dyn PacketForwarder>> = match config.protocol.as_str() {
            "gre" => Arc::new(Mutex::new(GreForwarder::new(&config).await?)),
            _ => return Err(crate::error::ForwarderError::Config(
                format!("Unsupported protocol: {}", config.protocol)
            ).into())
        };

        // 初始化转发器
        forwarder.lock().await.init().await?;

        Ok(forwarder)
    }
}

/// 转发统计信息
#[derive(Debug, Default, Clone)]
pub struct ForwardingStats {
    /// 转发的数据包数量
    pub packets_forwarded: u64,
    /// 转发失败的数据包数量
    pub packets_dropped: u64,
    /// 总转发字节数
    pub bytes_forwarded: u64,
    /// 最后一次转发时间
    pub last_forward_time: Option<std::time::SystemTime>,
}

/// 转发监控器
pub struct ForwardingMonitor {
    stats: Arc<Mutex<ForwardingStats>>,
}

impl ForwardingMonitor {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(Mutex::new(ForwardingStats::default())),
        }
    }

    /// 更新转发统计信息
    pub async fn update_stats(&self, bytes: usize, success: bool) {
        let mut stats = self.stats.lock().await;
        if success {
            stats.packets_forwarded += 1;
            stats.bytes_forwarded += bytes as u64;
        } else {
            stats.packets_dropped += 1;
        }
        stats.last_forward_time = Some(std::time::SystemTime::now());
    }

    /// 获取当前统计信息
    pub async fn get_stats(&self) -> ForwardingStats {
        self.stats.lock().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_forwarder_factory() {
        let config = ForwarderConfig {
            protocol: "gre".to_string(),
            destination: "127.0.0.1".to_string(),
            max_packet_size: 1500,
            queue_size: 1000,
            port: Some(9566),
            bind_device: None,
        };

        let forwarder = ForwarderFactory::create(config).await.unwrap();
        assert!(forwarder.lock().await.init().await.is_ok());
    }

    #[tokio::test]
    async fn test_forwarding_monitor() {
        let monitor = ForwardingMonitor::new();
        
        // 测试统计更新
        monitor.update_stats(100, true).await;
        monitor.update_stats(50, false).await;
        
        let stats = monitor.get_stats().await;
        assert_eq!(stats.packets_forwarded, 1);
        assert_eq!(stats.packets_dropped, 1);
        assert_eq!(stats.bytes_forwarded, 100);
    }
}