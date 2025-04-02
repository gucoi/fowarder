use async_trait::async_trait;
use crate::{
    capture::packet::PacketInfo,
    protocol::common::PacketStats,
    cli::ForwarderConfig,
    error::Result,
    forwarder::state::ForwarderState,
    errror::ForwarderError,
};

#[async_trait]
pub trait PacketForwarder: Send + Sync {
    /// 获取转发器类型
    fn forwarder_type(&self) -> &str;
    
    /// 初始化转发器
    async fn init(&mut self) -> Result<()>;
    
    /// 转发数据包
    async fn forward_packet(&mut self, packet: &PacketInfo, forward_config: &ForwarderConfig) -> Result<()>;
    
    /// 获取统计信息
    async fn get_stats(&self) -> Result<PacketStats>;

    /// 获取当前状态
    async fn get_state(&self) -> ForwarderState;
    
    /// 暂停转发
    async fn pause(&mut self) -> Result<()>;
    
    /// 恢复转发
    async fn resume(&mut self) -> Result<()>;
    
    /// 关闭转发器
    async fn shutdown(&mut self) -> Result<()>;
    
    /// 批量转发数据包
    async fn forward_packet_batch(&mut self, packets: &[PacketInfo]) -> Result<()> {
        for packet in packets {
            self.forward_packet(packet, &self.config).await?;
        }
        Ok(())
    }
    
    /// 获取建议的批处理大小
    fn suggested_batch_size(&self) -> usize {
        1024 // 默认批处理大小
    }

    // 新增必要的错误处理方法
    async fn handle_error(&self, error: ForwarderError) {
        // 错误处理逻辑
    }

    // 新增资源清理方法
    async fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}

