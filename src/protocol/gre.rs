use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::Ipv4Addr;
use crate::capture::{PacketCapture, PacketInfo};
use crate::error::{Result, ForwarderError};
use super::common::{Protocol, ProtocolType, Header};
use super::ipv4::Ipv4Header;

/// GRE 标志位
#[derive(Debug, Clone, Copy)]
pub struct GreFlags {
    pub checksum: bool,
    pub routing: bool,
    pub key: bool,
    pub sequence: bool,
    pub strict_source_route: bool,
    pub recursion_control: u8,
    pub version: u8,
}

impl Default for GreFlags {
    fn default() -> Self {
        Self {
            checksum: false,            // 默认不启用校验和
            routing: false,             // 默认不启用路由
            key: false,                 // 默认不使用密钥
            sequence: false,            // 默认不使用序列号
            strict_source_route: false, // 默认不启用严格源路由
            recursion_control: 0,       // 默认无递归控制
            version: 0,                 // 默认使用 GRE Version 0
        }
    }
}

impl GreFlags {
    pub fn to_bits(&self) -> u16 {
        let mut bits = 0u16;
        if self.checksum { bits |= 0x8000; }
        if self.routing { bits |= 0x4000; }
        if self.key { bits |= 0x2000; }
        if self.sequence { bits |= 0x1000; }
        if self.strict_source_route { bits |= 0x0800; }
        bits |= ((self.recursion_control & 0x7) as u16) << 5;
        bits |= (self.version & 0x7) as u16;
        bits
    }
    
    pub fn from_bits(bits: u16) -> Self {
        Self {
            checksum: (bits & 0x8000) != 0,
            routing: (bits & 0x4000) != 0,
            key: (bits & 0x2000) != 0,
            sequence: (bits & 0x1000) != 0,
            strict_source_route: (bits & 0x0800) != 0,
            recursion_control: ((bits >> 5) & 0x7) as u8,
            version: (bits & 0x7) as u8,
        }
    }
}

/// GRE头部
#[derive(Debug, Clone)]
pub struct GreHeader {
    pub flags: GreFlags,
    pub protocol_type: ProtocolType,
    pub checksum: Option<u16>,
    pub offset: Option<u16>,
    pub key: Option<u32>,
    pub sequence: Option<u32>,
}

impl GreHeader {
    pub fn new(tp: ProtocolType) -> Self {
        Self {
            flags: GreFlags::default(),
            protocol_type: tp,
            checksum: None,
            offset: None,
            key: None,
            sequence: None,
        }
    }
    pub fn with_key(mut self, key: u32) -> Self{
        self.flags.key = true;
        self.key = Some(key);
        self
    }

    pub fn with_checksum(mut self) -> Self {
        self.flags.checksum = true;
        self
    }
}

impl Protocol for GreHeader {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Gre
    }
    
    fn header_len(&self) -> usize {
        let mut len = 4; // 基础头部长度
        if self.flags.checksum || self.flags.routing {
            len += 4;
        }
        if self.flags.key {
            len += 4;
        }
        if self.flags.sequence {
            len += 4;
        }
        len
    }
    
    fn total_len(&self) -> usize {
        self.header_len()
    }
    
    fn compute_checksum(&self) -> u16 {
        // GRE校验和计算实现
        0 // TODO
    }
}

impl Header for GreHeader {
    fn write_to(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u16(self.flags.to_bits());
        buf.put_u16(self.protocol_type as u16);
        
        if self.flags.checksum || self.flags.routing {
            if let Some(checksum) = self.checksum {
                buf.put_u16(checksum);
            } else {
                buf.put_u16(0);
            }
            if let Some(offset) = self.offset {
                buf.put_u16(offset);
            } else {
                buf.put_u16(0);
            }
        }
        
        if self.flags.key {
            if let Some(key) = self.key {
                buf.put_u32(key);
            }
        }
        
        if self.flags.sequence {
            if let Some(sequence) = self.sequence {
                buf.put_u32(sequence);
            }
        }
        
        Ok(())
    }
    
    fn read_from(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(crate::error::ForwarderError::Protocol(
                "GRE header too short".into()
            ).into());
        }
        
        let flags = GreFlags::from_bits(buf.get_u16());
        let protocol_type = match buf.get_u16() {
            0x0800 => ProtocolType::Ipv4,
            0x86DD => ProtocolType::Ipv6,
            pt => return Err(crate::error::ForwarderError::Protocol(
                format!("Unknown protocol type: 0x{:04x}", pt)
            ).into()),
        };
        
        let mut checksum = None;
        let mut offset = None;
        let mut key = None;
        let mut sequence = None;
        
        if flags.checksum || flags.routing {
            if buf.remaining() < 4 {
                return Err(crate::error::ForwarderError::Protocol(
                    "GRE checksum/offset fields missing".into()
                ).into());
            }
            checksum = Some(buf.get_u16());
            offset = Some(buf.get_u16());
        }
        
        if flags.key {
            if buf.remaining() < 4 {
                return Err(crate::error::ForwarderError::Protocol(
                    "GRE key field missing".into()
                ).into());
            }
            key = Some(buf.get_u32());
        }
        
        if flags.sequence {
            if buf.remaining() < 4 {
                return Err(crate::error::ForwarderError::Protocol(
                    "GRE sequence field missing".into()
                ).into());
            }
            sequence = Some(buf.get_u32());
        }
        
        Ok(Self {
            flags,
            protocol_type,
            checksum,
            offset,
            key,
            sequence,
        })
    }
}


pub struct GrePacketBuilder {
    /// GRE头部
    header: GreHeader,
    /// 内部IP头部
    inner_ip_header: Option<Ipv4Header>,
    /// 负载数据
    payload: Option<Bytes>,
    /// 是否自动计算校验和
    compute_checksum: bool,
}

impl GrePacketBuilder {
    /// 创建新的GRE数据包构建器
    pub fn new() -> Self {
        Self {
            header: GreHeader::new(ProtocolType::Ipv4),
            inner_ip_header: None,
            payload: None,
            compute_checksum: false,
        }
    }

    /// 设置GRE Key
    pub fn key(mut self, key: u32) -> Self {
        self.header = self.header.with_key(key);
        self
    }

    /// 启用校验和
    pub fn with_checksum(mut self) -> Self {
        self.header = self.header.with_checksum();
        self.compute_checksum = true;
        self
    }

    /// 设置序列号
    pub fn sequence(mut self, seq: u32) -> Self {
        self.header.flags.sequence = true;
        self.header.sequence = Some(seq);
        self
    }

    /// 设置内部IP头部
    pub fn inner_ip(mut self, src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        self.inner_ip_header = Some(Ipv4Header::new(src, dst));
        self
    }

    /// 设置负载数据
    pub fn payload(mut self, payload: impl Into<Bytes>) -> Self {
        self.payload = Some(payload.into());
        self
    }

    /// 构建GRE数据包
    pub fn build(&mut self, packet: &PacketInfo) -> Result<Bytes> {
        // 预分配足够大小的buffer,避免重新分配
        let total_len = self.header.header_len() + packet.payload.len();
        let mut buf = BytesMut::with_capacity(total_len);
        
        // 1. 写入GRE头部
        self.header.write_to(&mut buf)?;

        // 2. 重新构建新的包
        buf.extend_from_slice(&PacketCapture::build_packet(&packet));

        // 4. 如果需要计算校验和
        if self.compute_checksum {
            let checksum = self.calculate_checksum(&buf);
            // 在GRE头部之后写入校验和
            buf[4..6].copy_from_slice(&checksum.to_be_bytes());
        }

        // 添加错误处理
        if buf.len() - 4 > packet.header.length as usize {
            return Err(ForwarderError::PacketTooLarge {
                size: buf.len(),
                max: packet.header.length as usize,
            });
        }

        Ok(buf.freeze())
    }

    /// 计算GRE校验和
    fn calculate_checksum(&self, data: &[u8]) -> u16 {
        let mut sum = 0u32;

        // 以16位为单位计算总和
        for chunk in data.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                // 如果是奇数字节,补0
                sum += (chunk[0] as u32) << 8;
            }
        }

        // 处理进位
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // 取反
        !sum as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gre_flags() {
        let flags = GreFlags {
            checksum: true,
            routing: false,
            key: true,
            sequence: false,
            strict_source_route: false,
            recursion_control: 0,
            version: 0,
        };
        
        let bits = flags.to_bits();
        let parsed = GreFlags::from_bits(bits);
        
        assert_eq!(parsed.checksum, flags.checksum);
        assert_eq!(parsed.key, flags.key);
    }
    
    #[test]
    fn test_gre_header() {
        let header = GreHeader {
            flags: GreFlags {
                checksum: true,
                routing: false,
                key: true,
                sequence: false,
                strict_source_route: false,
                recursion_control: 0,
                version: 0,
            },
            protocol_type: ProtocolType::Ipv4,
            checksum: Some(0x1234),
            offset: Some(0),
            key: Some(0x12345678),
            sequence: None,
        };
        
        let mut buf = BytesMut::new();
        header.write_to(&mut buf).unwrap();
        
        let mut bytes = buf.freeze();
        let parsed = GreHeader::read_from(&mut bytes).unwrap();
        
        assert_eq!(parsed.flags.to_bits(), header.flags.to_bits());
        assert_eq!(parsed.protocol_type, header.protocol_type);
        assert_eq!(parsed.checksum, header.checksum);
        assert_eq!(parsed.key, header.key);
    }
}