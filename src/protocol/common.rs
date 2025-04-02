use bytes::{Bytes, BytesMut};
use std::net::IpAddr;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, Duration};

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

    /// 获取缓存键(用于优化重复处理)
    fn cache_key(&self) -> Option<u64> {
        None
    }
    
    /// 是否需要优化处理
    fn needs_optimization(&self) -> bool {
        false
    }
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
    cached_hash: Option<u64>,
}

impl AddressInfo {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: Option<u16>, dst_port: Option<u16>) -> Self {
        let mut info = Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            cached_hash: None,
        };
        info.update_cache();
        info
    }

    fn update_cache(&mut self) {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        self.src_ip.hash(&mut hasher);
        self.dst_ip.hash(&mut hasher);
        self.src_port.hash(&mut hasher);
        self.dst_port.hash(&mut hasher);
        self.cached_hash = Some(hasher.finish());
    }

    pub fn get_hash(&self) -> u64 {
        self.cached_hash.unwrap_or_else(|| {
            use std::hash::{Hash, Hasher};
            use std::collections::hash_map::DefaultHasher;
            
            let mut hasher = DefaultHasher::new();
            self.src_ip.hash(&mut hasher);
            self.dst_ip.hash(&mut hasher);
            self.src_port.hash(&mut hasher);
            self.dst_port.hash(&mut hasher);
            hasher.finish()
        })
    }
}

/// 数据包统计 - 需要优化内存布局
#[derive(Debug, Default)]
pub struct PacketStats {
    total_packets: AtomicU64,
    total_bytes: AtomicU64,
    error_packets: AtomicU64,
    last_update: std::sync::atomic::AtomicU64,
    avg_packet_size: AtomicU64,
    throughput_bps: AtomicU64,
    // 添加批量统计缓存,减少原子操作
    batch_stats: parking_lot::RwLock<BatchStats>,
}

// 新增批量统计结构
#[derive(Default)]
struct BatchStats {
    packet_count: u32,
    byte_count: u64,
    last_update: Instant,
}

impl PacketStats {
    pub fn increment_packets(&self) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn add_bytes(&self, bytes: u64) {
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    
    pub fn increment_errors(&self) {
        self.error_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn update_metrics(&self) {
        let now = Instant::now().elapsed().as_secs();
        let last = self.last_update.load(Ordering::Relaxed);
        
        if now > last {
            let total_bytes = self.total_bytes.load(Ordering::Relaxed);
            let total_packets = self.total_packets.load(Ordering::Relaxed);
            
            // 计算平均包大小
            if total_packets > 0 {
                self.avg_packet_size.store(total_bytes / total_packets, Ordering::Relaxed);
            }
            
            // 计算吞吐量 (bytes per second)
            let time_diff = now - last;
            if time_diff > 0 {
                let throughput = total_bytes / time_diff;
                self.throughput_bps.store(throughput, Ordering::Relaxed);
            }
            
            self.last_update.store(now, Ordering::Relaxed);
        }
    }
    
    pub fn get_throughput(&self) -> u64 {
        self.throughput_bps.load(Ordering::Relaxed)
    }
    
    pub fn get_avg_packet_size(&self) -> u64 {
        self.avg_packet_size.load(Ordering::Relaxed)
    }

    // 批量更新方法
    pub fn batch_update(&self, packets: u32, bytes: u64) {
        let mut stats = self.batch_stats.write();
        stats.packet_count += packets;
        stats.byte_count += bytes;
        
        // 定期刷新到原子计数器
        if stats.last_update.elapsed() > Duration::from_secs(1) {
            self.total_packets.fetch_add(stats.packet_count as u64, Ordering::Relaxed);
            self.total_bytes.fetch_add(stats.byte_count, Ordering::Relaxed);
            *stats = BatchStats::default();
        }
    }
}

impl TryFrom<u8> for ProtocolType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x06 => Ok(ProtocolType::Tcp),
            0x11 => Ok(ProtocolType::Udp),
            0x2F => Ok(ProtocolType::Gre),
            0x0C => Ok(ProtocolType::Vxlan),
            _ => Err("Unknown protocol type"),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_protocol_type() {
        assert_eq!(ProtocolType::Ipv4 as u16, 0x0800);
        assert_eq!(ProtocolType::Tcp as u8, 0x06);
    }

    #[test]
    fn test_address_info() {
        let addr_info = AddressInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: Some(8080),
            dst_port: Some(80),
            cached_hash: None,
        };
        
        assert_eq!(addr_info.src_port.unwrap(), 8080);
        assert_eq!(addr_info.dst_port.unwrap(), 80);
    }

    #[test]
    fn test_packet_stats() {
        let stats = PacketStats::default();
        stats.increment_packets();
        stats.add_bytes(15000);
        stats.increment_errors();
        
        assert_eq!(stats.total_packets.load(Ordering::Relaxed), 1);
        assert_eq!(stats.total_bytes.load(Ordering::Relaxed), 15000);
        assert_eq!(stats.error_packets.load(Ordering::Relaxed), 1);
    }
}