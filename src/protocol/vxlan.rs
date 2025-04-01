use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::Result;
use super::common::{Protocol, ProtocolType, Header};

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
    pub payload: Option<Bytes>,
}

impl VxlanPacketBuilder {
    pub fn new() -> Self {
        Self {
            header: VxlanHeader::default(),
            payload: None,
        }
    }
}

#[cfg(test)]
mod tests {
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
}