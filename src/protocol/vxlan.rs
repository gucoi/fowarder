use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::Result;
use super::common::{Protocol, ProtocolType, Header};
use crate::capture::PacketCapture;
use crate::capture::packet::{PacketInfo, PacketHeader};

/// VXLAN头部标志位
#[derive(Debug, Clone, Copy, Default)]
pub struct VxlanFlags {
    pub vni_present: bool,
    pub reserved: u32,
}

impl VxlanFlags {
    pub fn to_bits(&self) -> u8 {
        let mut bits = 0u8;
        if self.vni_present { bits |= 0x08; }
        bits
    }
    
    pub fn from_bits(bits: u8) -> Self {
        Self {
            vni_present: (bits & 0x08) != 0,
            reserved: 0,
        }
    }
}

/// VXLAN头部
#[derive(Debug, Clone, Default)]
pub struct VxlanHeader {
    pub flags: VxlanFlags,
    pub vni: u32,  // 24-bit VNI
    pub reserved: u32,
}

impl Protocol for VxlanHeader {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Vxlan
    }
    
    fn header_len(&self) -> usize {
        8 // VXLAN header is always 8 bytes
    }
    
    fn total_len(&self) -> usize {
        self.header_len()
    }
    
    fn compute_checksum(&self) -> u16 {
        0 // VXLAN doesn't use checksums
    }
}

impl Header for VxlanHeader {
    fn write_to(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u8(self.flags.to_bits());
        buf.put_bytes(0, 3); // Reserved
        
        // VNI is 24 bits, pad with reserved bits
        buf.put_u8(((self.vni >> 16) & 0xFF) as u8);
        buf.put_u8(((self.vni >> 8) & 0xFF) as u8);
        buf.put_u8((self.vni & 0xFF) as u8);
        buf.put_u8(0); // Reserved
        
        Ok(())
    }
    
    fn read_from(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 8 {
            return Err(crate::error::ForwarderError::Protocol(
                "VXLAN header too short".into()
            ).into());
        }
        
        let flags = VxlanFlags::from_bits(buf.get_u8());
        buf.advance(3); // Skip reserved bytes
        
        let vni = ((buf.get_u8() as u32) << 16) |
                 ((buf.get_u8() as u32) << 8) |
                 (buf.get_u8() as u32);
        buf.advance(1); // Skip reserved byte
        
        Ok(Self {
            flags,
            vni,
            reserved: 0,
        })
    }
}

/// VXLAN隧道端点信息
#[derive(Debug, Clone)]
pub struct VxlanEndpoint {
    pub vni: u32,
    pub remote_ip: std::net::IpAddr,
    pub remote_port: u16,
    pub local_ip: std::net::IpAddr,
    pub local_port: u16,
}

#[derive(Debug, Clone)]
pub struct VxlanPacketBuilder {
    pub header : VxlanHeader,
}

impl VxlanPacketBuilder {
    pub fn new() -> Self {
        Self {
            header: VxlanHeader::default(),
        }
    }

    pub fn build(&mut self, packet: &PacketInfo) -> Result<Bytes> {
        let mut buf = BytesMut::with_capacity(self.header.header_len());

        // 设置VNI和标志
        self.header.flags.vni_present = true;
        // 处理 Option<NonZeroU32> 到 u32 的转换
        self.header.vni = packet.vni.map(|n| n.get()).unwrap_or(0);

        // 写入VXLAN头部
        self.header.write_to(&mut buf)?;

        // 使用PacketCapture::build_packet构建原始数据包
        let packet_data = PacketCapture::build_packet(packet);
        buf.extend_from_slice(&packet_data);

        Ok(buf.freeze())
    }

    pub fn set_vni(&mut self, vni: u32) -> &mut Self {
        self.header.vni = vni;
        self.header.flags.vni_present = true;
        self
    }

    pub fn set_endpoint(&mut self, endpoint: &VxlanEndpoint) -> &mut Self {
        self.header.vni = endpoint.vni;
        self.header.flags.vni_present = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZero, sync::Arc};


    use super::*;
    
    #[test]
    fn test_vxlan_flags() {
        let flags = VxlanFlags {
            vni_present: true,
            reserved: 0,
        };
            
        let bits = flags.to_bits();
        let parsed = VxlanFlags::from_bits(bits);
        
        assert_eq!(parsed.vni_present, flags.vni_present);
    }
    
    #[test]
    fn test_vxlan_header() {
        let header = VxlanHeader {
            flags: VxlanFlags {
                vni_present: true,
                reserved: 0,
            },
            vni: 0x123456,
            reserved: 0,
        };
        
        let mut buf = BytesMut::new();
        header.write_to(&mut buf).unwrap();
           
        let mut bytes = buf.freeze();
        let parsed = VxlanHeader::read_from(&mut bytes).unwrap();
        
        assert_eq!(parsed.flags.vni_present, header.flags.vni_present);
        assert_eq!(parsed.vni, header.vni);
    }

    #[test]
    fn test_vxlan_packet_build() {
        let mut builder = VxlanPacketBuilder::new();
        let test_data = vec![1, 2, 3, 4];
        let packet = PacketInfo {
            payload: Arc::new(Bytes::from(test_data.clone())),
            vni: NonZero::new(1234),
            header: PacketHeader::default(),
        };

        let result = builder.build(&packet).unwrap();
        
        // 验证长度
        assert_eq!(result.len(), 8 + test_data.len()); // VXLAN header + payload
        
        // 验证VNI
        let mut bytes = result.slice(0..);
        let parsed = VxlanHeader::read_from(&mut bytes).unwrap();
        assert_eq!(parsed.vni, 1234);
        
        // 验证payload
        assert_eq!(&bytes[..], &test_data[..]);
    }
}