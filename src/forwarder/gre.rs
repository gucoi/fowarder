use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use async_trait::async_trait;
use tokio::net::UdpSocket;
use crate::protocol::gre::GrePacketBuilder;
use super::base::PacketForwarder;
use crate::capture::packet::PacketInfo;
use crate::cli::ForwarderConfig;
use crate::error::{ForwarderError, Result};

pub struct GreForwarder {
    socket: UdpSocket,
    packet_builder: GrePacketBuilder,
}

impl GreForwarder {
    pub async fn new(config: &ForwarderConfig) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        if Some(bind_device) = config.bind_device {
            socket.bind_device(bind_device);
        }

        Ok(Self {
            socket,
            packet_builder: GrePacketBuilder::new(),
        })
    }
}

#[async_trait]
impl PacketForwarder for GreForwarder {
    async fn init(&mut self) -> Result<()> {
        // 建立GRE隧道
        Ok(())
    }
    
    async fn forward_packet(&mut self, packet: &PacketInfo, forwarder_config: &ForwarderConfig) -> Result<()> {
        let gre_packet = self.packet_builder.build(packet)?;
        
        let ip_addr = forwarder_config.destination.parse::<Ipv4Addr>().map_err(|e| {
            ForwarderError::Config("Forwarder destination config invalid".to_string())
        })?;
        let socket_addr = SocketAddr::new(IpAddr::V4(ip_addr), forwarder_config.port);

        self.socket.send_to(&gre_packet, socket_addr).await?;
        Ok(())
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        // 清理GRE隧道
        Ok(())
    }
}