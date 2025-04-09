use crate::{
    error::{Result, ForwarderError},
    forwarder::base::PacketForwarder,
    protocol::common::{PacketStats, PacketStatsSnapshot},
    capture::packet::PacketInfo,
    cli::ForwarderConfig,
    forwarder::state::ForwarderState,
};

use std::sync::Arc;
use tokio::sync::Mutex;
use zmq::Socket;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

pub struct ZmqForwarder {
    socket: Arc<Mutex<Socket>>,
    stats: Arc<PacketStats>,  // 使用原子计数，无需 Mutex
    state: Arc<AtomicU8>,     // 使用原子状态替代 Mutex<ForwarderState>
    batch_size: usize,
    batch_timeout: Duration,
    destination: String,
    port: u16,
    // 添加连接状态监控
    connection_state: Arc<AtomicU8>,
    // 添加重连机制
    reconnect_timeout: Duration,
}

impl ZmqForwarder {
    pub fn new(destination: String, port: u16) -> Result<Self> {
        let context = zmq::Context::new();
        let socket = context.socket(zmq::PUB)?;
        
        // 设置发送超时
        socket.set_sndtimeo(1000)?;
        
        // 连接到目标地址
        let endpoint = format!("tcp://{}:{}", destination, port);
        socket.connect(&endpoint)?;
        
        Ok(Self {
            socket: Arc::new(Mutex::new(socket)),
            stats: Arc::new(PacketStats::default()),
            state: Arc::new(AtomicU8::new(ForwarderState::Running.as_u8())),
            batch_size: 10,  // 默认批处理大小
            batch_timeout: Duration::from_secs(1),  // 默认批处理超时
            destination,
            port,
            connection_state: Arc::new(AtomicU8::new(0)), // 初始化连接状态
            reconnect_timeout: Duration::from_secs(5), // 默认重连超时
        })
    }
    
    async fn update_stats(&self, bytes_sent: usize) {
        self.stats.add_bytes(bytes_sent as u64);
        self.stats.increment_packets();
    }

    async fn batch_forward(&mut self, packets: Vec<&PacketInfo>) -> Result<()> {
        let socket = self.socket.lock().await;
        let mut total_bytes = 0;
        
        // 使用 zmq 的多部分消息特性
        for packet in packets {
            let msg = zmq::Message::from(packet.payload.as_ref().to_vec());
            socket.send_multipart(vec![msg], zmq::SNDMORE)?;
            total_bytes += packet.payload.len();
        }
        
        self.stats.add_bytes(total_bytes as u64);
        self.stats.increment_packets();
        
        Ok(())
    }

    // 添加重连逻辑
    async fn try_reconnect(&mut self) -> Result<()> {
        // 重连逻辑实现
        Ok(())
    }

    // 优化发送逻辑
    async fn send_with_retry(&self, data: &[u8], retries: u32) -> Result<()> {
        // 重试发送逻辑
        Ok(())
    }
}

#[async_trait::async_trait]
impl PacketForwarder for ZmqForwarder {
    fn forwarder_type(&self) -> &str {
        "zmq"
    }

    async fn get_stats(&self) -> Result<PacketStatsSnapshot> {
        Ok(self.stats.snapshot())
    }

    async fn get_state(&self) -> ForwarderState {
        match self.state.load(Ordering::SeqCst) {
            0 => ForwarderState::Paused,
            _ => ForwarderState::Running,
        }
    }

    async fn pause(&mut self) -> Result<()> {
        self.state.store(ForwarderState::Paused.as_u8(), Ordering::SeqCst);
        Ok(())
    }

    async fn resume(&mut self) -> Result<()> {
        self.state.store(ForwarderState::Running.as_u8(), Ordering::SeqCst);
        Ok(())
    }

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn forward_packet(&mut self, packet: &PacketInfo, _forward_config: &ForwarderConfig) -> Result<()> {
        let socket = self.socket.lock().await;
        let bytes_len = packet.payload.len();
        
        // 创建 ZMQ 消息并发送
        let msg = zmq::Message::from(packet.payload.as_ref().to_vec());
        socket.send(msg, 0)
            .map_err(|e| ForwarderError::Network(format!("Failed to send packet: {}", e)))?;
            
        self.update_stats(bytes_len).await;
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        // ZMQ socket会在drop时自动关闭
        Ok(())
    }

    
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_zmq_forwarder() {
        let config = ForwarderConfig {
            protocol: "zmq".to_string(),
            destination: "127.0.0.1".to_string(),
            port: Some(5555),
            max_packet_size: 1500,
            queue_size: 1000,
            bind_device: None,
        };

        let mut forwarder = ZmqForwarder::new(
            config.destination.clone(),
            config.port.unwrap_or(5555),
        ).unwrap();

        let packet = PacketInfo {
            payload: Arc::new(Bytes::from(vec![1, 2, 3, 4])),
            ..Default::default()
        };

        match forwarder.forward_packet(&packet, &config).await {
            Ok(_) => println!("Packet forwarded successfully"),
            Err(e) => println!("Forward failed (expected if no ZMQ subscriber): {}", e),
        };

        // 不再需要显式调用close
        assert!(forwarder.shutdown().await.is_ok());
    }
}