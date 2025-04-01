use async_trait::async_trait;
use crate::capture::packet::PacketInfo;
use crate::ForwarderConfig;
use crate::error::Result;

#[async_trait]
pub trait PacketForwarder: Send + Sync {
    /// 初始化转发器
    async fn init(&mut self) -> Result<()>;
    
    /// 转发数据包
    async fn forward_packet(&mut self, packet: &PacketInfo, forward_config: &ForwarderConfig) -> Result<()>;
    
    /// 关闭转发器
    async fn shutdown(&mut self) -> Result<()>;
}

