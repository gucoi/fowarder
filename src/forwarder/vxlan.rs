use std::{net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket}, os::windows::io::FromRawSocket};
use anyhow::Ok;
use socket2::{Domain, Protocol, Socket, Type};
use crate::{cli::ForwarderConfig, error::Result, protocol::vxlan::VxlanPacketBuilder};
use super::PacketForwarder;
use libc;


pub struct VxlanForwarder {
    socket: UdpSocket,
    packet_builder: VxlanPacketBuilder,
}

impl VxlanForwarder {
    pub async fn new(config: &ForwarderConfig) -> Result<Self> {
        let socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        socket2.set_reuse_address(true)?;

        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)?;

        if Some(bind_device) = config.bind_device {
            let index = unsafe {
                libc::if_nametoindex(bind_device);
            };
            socket2.bind_device_by_index(index)?;
        }

        let socket = unsafe {
            UdpSocket::from_raw_socket(socket2.into_raw_fd())
        };

        socket.set_nonblocking(true)?;

        Ok(Self{
            socket,
            packet_builder: VxlanPacketBuilder::new(), 
        })
    }
}

#[async_trait]
impl PacketForwarder for VxlanForwarder {
}