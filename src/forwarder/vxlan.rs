use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, os::windows::io::FromRawSocket};
use socket2::{Domain, Protocol, Socket, Type};
use crate::{cli::ForwarderConfig, 
    error::Result, error::ForwarderError, 
    protocol::vxlan::VxlanPacketBuilder};
use super::PacketForwarder;
use libc;
use std::sync::{Arc, atomic::{AtomicU8, Ordering}};
use crate::protocol::common::{PacketStats, PacketStatsSnapshot};
use crate::forwarder::state::ForwarderState;

use std::os::windows::io::IntoRawSocket;
use async_trait::async_trait;
use tokio::net::UdpSocket;
use crate::capture::packet::PacketInfo;
use crate::platform::interface::create_interface;

pub struct VxlanForwarder {
    socket: UdpSocket,
    packet_builder: VxlanPacketBuilder,
    stats: Arc<PacketStats>,
    state: Arc<AtomicU8>, // 使用原子状态替代 Mutex<ForwarderState>
}

impl VxlanForwarder {
    pub async fn new(config: &ForwarderConfig) -> Result<Self> {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
            .map_err(|e| ForwarderError::Interface(format!("Failed to create socket: {}", e)))?;

        if let Some(bind_device) = &config.bind_device {
            socket.set_reuse_address(true).map_err(|e| {
                ForwarderError::Interface(format!("Failed to set reuse address: {}", e))
            })?;
            socket.bind(&socket2::SockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
                .map_err(|e| ForwarderError::Interface(format!("Failed to bind socket: {}", e)))?;

            let interface = create_interface();
            interface.bind_to_interface(&socket, bind_device).map_err(|e| {
                ForwarderError::Interface(format!("Failed to bind to interface: {}", e))
            })?;
        } else {
            socket.bind(&socket2::SockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
                .map_err(|e| ForwarderError::Interface(format!("Failed to bind socket: {}", e)))?;
        }

        // 设置非阻塞模式
        socket.set_nonblocking(true).map_err(|e| {
            ForwarderError::Interface(format!("Failed to set non-blocking mode: {}", e))
        })?;

        // 转换为tokio的UDP socket
        let std_socket = unsafe { std::net::UdpSocket::from_raw_socket(socket.into_raw_socket()) };
        
        let udp_socket = UdpSocket::from_std(std_socket)
            .map_err(|e| ForwarderError::Interface(format!("Failed to convert to tokio UdpSocket: {}", e)))?;

        Ok(Self {
            socket: udp_socket,
            packet_builder: VxlanPacketBuilder::new(),
            stats: Arc::new(PacketStats::default()),
            state: Arc::new(AtomicU8::new(ForwarderState::Running.as_u8())), // 初始化状态为运行
        })
    }
}

#[async_trait]
impl PacketForwarder for VxlanForwarder {
    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    fn forwarder_type(&self) -> &str {
        "vxlan"
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
    
    async fn forward_packet(&mut self, packet: &PacketInfo, forwarder_config: &ForwarderConfig) -> Result<()> {
        let vxlan_packet = self.packet_builder.build(packet)
            .map_err(|e| ForwarderError::Protocol(format!("Failed to build VXLAN packet: {}", e)))?;
        
        let ip_addr = forwarder_config.destination.parse::<Ipv4Addr>().map_err(|_| {
            ForwarderError::Config("Forwarder destination config invalid".to_string())
        })?;
        
        // VXLAN typically uses port 4789
        let port = forwarder_config.port.unwrap_or(4789);
        let socket_addr = SocketAddr::new(IpAddr::V4(ip_addr), port);

        self.socket.send_to(&vxlan_packet, socket_addr).await?;
        Ok(())
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_vxlan_forwarder() {
        let config = ForwarderConfig {
            protocol: "vxlan".to_string(),
            destination: "127.0.0.1".to_string(),
            port: Some(4789),
            max_packet_size: 1500,
            bind_device: None,
            queue_size: 100,
        };
        
        let mut forwarder = VxlanForwarder::new(&config).await.unwrap();
        
        let packet = PacketInfo {
            pay_load: Some(Bytes::from(vec![1, 2, 3, 4])),
            vni: Some(1000),
            ..Default::default()
        };
        
        assert!(forwarder.forward_packet(&packet, &config).await.is_ok());
    }
}