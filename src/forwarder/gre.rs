use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::windows::io::{IntoRawSocket, FromRawSocket};
use std::sync::{Arc, atomic::{AtomicU8, Ordering}};
use async_trait::async_trait;
use tokio::net::UdpSocket;
use crate::protocol::gre::GrePacketBuilder;
use super::base::PacketForwarder;
use crate::capture::packet::PacketInfo;
use crate::cli::ForwarderConfig;
use crate::error::{ForwarderError, Result};
use crate::platform::interface::create_interface;
use crate::forwarder::state::ForwarderState;
use crate::protocol::common::{PacketStats, PacketStatsSnapshot};

pub struct GreForwarder {
    socket: UdpSocket,
    packet_builder: GrePacketBuilder,
    stats: Arc<PacketStats>,
    state: Arc<AtomicU8>, 
}

impl GreForwarder {
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

        // 转换为原始socket，然后构建标准库的UDP socket
        let raw_socket = socket.into_raw_socket();
        let std_socket = unsafe { std::net::UdpSocket::from_raw_socket(raw_socket) };
        
        // 转换为tokio的UDP socket
        let udp_socket = UdpSocket::from_std(std_socket).map_err(|e| {
            ForwarderError::Interface(format!("Failed to convert to tokio UdpSocket: {}", e))
        })?;
    
        Ok(Self {
            socket: udp_socket,
            packet_builder: GrePacketBuilder::new(),
            stats: Arc::new(PacketStats::default()),
            state: Arc::new(AtomicU8::new(ForwarderState::Running.as_u8())),
        })
    }
}

#[async_trait]
impl PacketForwarder for GreForwarder {
    
    async fn resume(&mut self) -> Result<()> {
        self.state.store(ForwarderState::Running.as_u8(), Ordering::SeqCst);
        Ok(())
    }

    fn forwarder_type(&self) -> &str {
        "GRE"
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

    async fn init(&mut self) -> Result<()> {
        // 建立GRE隧道
        Ok(())
    }
    
    async fn forward_packet(&mut self, packet: &PacketInfo, forwarder_config: &ForwarderConfig) -> Result<()> {
        let gre_packet = self.packet_builder.build(packet)?;
        
        let ip_addr = forwarder_config.destination.parse::<Ipv4Addr>().map_err(|e| {
            ForwarderError::Config("Forwarder destination config invalid".to_string())
        })?;
        let socket_addr = SocketAddr::new(IpAddr::V4(ip_addr), forwarder_config.port.unwrap_or(9266));

        self.socket.send_to(&gre_packet, socket_addr).await?;
        Ok(())
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        // 清理GRE隧道
        Ok(())
    }
}