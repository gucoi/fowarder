use bytes::{Bytes, BytesMut};
use std::net::IpAddr;

/// 协议类型枚举
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtocolType {
    Ethernet = 0x0001,
    Ipv4 = 0x0800,
    Ipv6 = 0x86DD,
    Gre = 0x2F,
    Tcp = 0x06,
    Udp = 0x11,
    Vxlan = 0x0C,
}

/// 基础协议trait
pub trait Protocol {
    /// 获取协议类型
    fn protocol_type(&self) -> ProtocolType;
    
    /// 获取头部长度
    fn header_len(&self) -> usize;
    
    /// 获取总长度(包括payload)
    fn total_len(&self) -> usize;
    
    /// 计算校验和
    fn compute_checksum(&self) -> u16;
}

/// 通用头部trait
pub trait Header: Protocol {
    /// 将头部序列化到buffer
    fn write_to(&self, buf: &mut BytesMut) -> crate::error::Result<()>;
    
    /// 从buffer解析头部
    fn read_from(buf: &mut Bytes) -> crate::error::Result<Self> where Self: Sized;
}

/// 地址信息
#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

/// 数据包统计
#[derive(Debug, Default)]
pub struct PacketStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub error_packets: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_type() {
        assert_eq!(ProtocolType::Ipv4 as u16, 0x0800);
        assert_eq!(ProtocolType::Tcp as u8, 0x06);
    }
}