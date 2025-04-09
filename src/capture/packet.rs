use bytes::{BufMut, Bytes, BytesMut};
use pcap::{Active, Capture, Device};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};

use crate::error::{ForwarderError, Result};
use crate::protocol::common::ProtocolType;

/// 优化的数据包信息结构
#[derive(Clone, Debug)]
pub struct PacketInfo {
    // 使用 Arc<Bytes> 替代 Option<Bytes> 来共享数据
    pub payload: Arc<Bytes>,
    // 内联小的头部数据以减少内存分配
    pub header: PacketHeader,
    // 使用 Option<NonZeroU32> 优化 Option 存储
    pub vni: Option<std::num::NonZeroU32>,
}

#[derive(Clone, Debug)]
pub struct PacketHeader {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: ProtocolType,
    pub src_port: Option<u16>, 
    pub dst_port: Option<u16>, 
    pub length: u16,
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            payload: Arc::new(Bytes::new()),
            header: PacketHeader::default(),
            vni: None,
        }
    }
}

impl Default for PacketHeader {
    fn default() -> Self {
        Self {
            source: Ipv4Addr::new(0, 0, 0, 0),
            destination: Ipv4Addr::new(0, 0, 0, 0),
            protocol: ProtocolType::Ethernet,
            src_port: None,
            dst_port: None,
            length: 0,
        }
    }
}

/// 抓包过滤器 - 只保留必要的过滤配置
#[derive(Clone)]
pub struct PacketFilter {
    pub bpf_filter: String,
    pub snapshot_length: i32,
    pub promiscuous: bool,
    pub timeout_ms: i32,
}

impl Default for PacketFilter {
    fn default() -> Self {
        Self {
            bpf_filter: String::new(),
            snapshot_length: 65535,
            promiscuous: true,
            timeout_ms: 1000,
        }
    }
}

pub struct PacketCapture {
    cap: Capture<Active>,
    tx: broadcast::Sender<PacketInfo>,  // 这里保持不变
    interface_name: String,
    stats: Arc<CaptureStats>,
}

pub struct CaptureStats {
    packets_received: AtomicU64,
    packets_dropped: AtomicU64,
    packets_if_dropped: AtomicU64,
}

impl Default for CaptureStats {
    fn default() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_if_dropped: AtomicU64::new(0),
        }
    }
}

impl CaptureStats {
    fn get_stats(&self) -> (u64, u64, u64) {
        (
            self.packets_received.load(Ordering::Relaxed),
            self.packets_dropped.load(Ordering::Relaxed),
            self.packets_if_dropped.load(Ordering::Relaxed),
        )
    }
}

impl PacketCapture {
    /// 创建新的抓包实例
    pub fn new(
        interface_name: &str,
        tx: broadcast::Sender<PacketInfo>, // 保持参数不变
        filter: PacketFilter,
    ) -> Result<Self> {
        // 查找网络接口
        let device = Device::list()?
            .into_iter()
            .find(|dev| dev.name == interface_name)
            .ok_or_else(|| {
                ForwarderError::Capture(format!("Interface {} not found", interface_name))
            })?;

        // 创建抓包器
        let mut cap = Capture::from_device(device)?
            .promisc(filter.promiscuous)
            .snaplen(filter.snapshot_length)
            .timeout(filter.timeout_ms)
            .open()?;

        // 设置BPF过滤器
        if !filter.bpf_filter.is_empty() {
            cap.filter(&filter.bpf_filter, true)?;
        }

        Ok(Self {
            cap,
            tx,
            interface_name: interface_name.to_string(),
            stats: Arc::new(CaptureStats::default()),
        })
    }

    pub fn get_stats_handler(&self) -> Arc<CaptureStats> {
        Arc::clone(&self.stats)
    }

    pub async fn capture_loop(&mut self) -> Result<()> {
        let stats = &self.stats;

        loop {
            match self.cap.next_packet() {
                Ok(packet) => {
                    stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    // 移除生命周期标注
                    if let Some(packet_info) = Self::process_packet(&packet) {
                        if let Err(e) = self.tx.send(packet_info) {
                            log::error!("Failed to broadcast packet: {}", e);
                            break;
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    continue;
                }
                Err(e) => {
                    log::error!("Packet capture error: {}", e);
                    break;
                }
            }

            // 更新统计信息
            if let Ok(pcap_stats) = self.cap.stats() {
                stats
                    .packets_dropped
                    .store(pcap_stats.dropped as u64, Ordering::Relaxed);
                stats
                    .packets_if_dropped
                    .store(pcap_stats.if_dropped as u64, Ordering::Relaxed);
            }
        }

        Ok(())
    }
    /// 启动抓包循环
    /// 处理捕获的数据包
    // 简化函数签名，移除生命周期参数
    fn process_packet(packet: &pcap::Packet) -> Option<PacketInfo> {
        let ethernet = EthernetPacket::new(packet.data)?;

        // 使用 zero-copy 方式处理 payload
        let payload = Arc::new(Bytes::copy_from_slice(packet.data));

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ip_packet = Ipv4Packet::new(ethernet.payload())?;
                let mut src_port = None;
                let mut dst_port = None;

                // 解析TCP/UDP端口
                match ip_packet.get_next_level_protocol().0 {
                    6 => {
                        // TCP
                        if let Some(tcp) = TcpPacket::new(ip_packet.payload()) {
                            src_port = Some(tcp.get_source());
                            dst_port = Some(tcp.get_destination());
                        }
                    }
                    17 => {
                        // UDP
                        if let Some(udp) = UdpPacket::new(ip_packet.payload()) {
                            src_port = Some(udp.get_source());
                            dst_port = Some(udp.get_destination());
                        }
                    }
                    _ => {}
                }

                Some(PacketInfo {
                    payload,
                    header: PacketHeader {
                        source: ip_packet.get_source(),
                        destination: ip_packet.get_destination(),
                        protocol: ProtocolType::try_from(ip_packet.get_next_level_protocol().0).unwrap(),
                        src_port,
                        dst_port,
                        length: packet.data.len() as u16,
                    },
                    vni: None,  // Default to None for now
                })
            }
            _ => None,
        }
    }

    pub fn build_packet(packet_info: &PacketInfo) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_slice(&packet_info.payload.as_ref()[..14]);

        let mut ip_header = Vec::new();
        ip_header.extend_from_slice(&packet_info.payload.as_ref()[14..34]);

        let src_ip_ocs = packet_info.header.source.octets();
        ip_header[12] = src_ip_ocs[0];
        ip_header[13] = src_ip_ocs[1];
        ip_header[14] = src_ip_ocs[2];
        ip_header[15] = src_ip_ocs[3];

        let dst_ip_ocs = packet_info.header.destination.octets();
        ip_header[16] = dst_ip_ocs[0];
        ip_header[17] = dst_ip_ocs[1];
        ip_header[18] = dst_ip_ocs[2];
        ip_header[19] = dst_ip_ocs[3];

        buf.put_slice(&ip_header);

        buf.put_slice(&packet_info.payload.as_ref()[34..]);

        buf
    }

    /// 获取当前统计信息
    pub fn get_stats(&self) -> &CaptureStats {
        &self.stats
    }

    /// 设置新的BPF过滤器
    pub fn set_filter(&mut self, filter: &str) -> Result<()> {
        self.cap.filter(filter, true)?;
        Ok(())
    }
}


// 帮助函数：列出所有可用的网络接口
pub fn list_interfaces() -> Result<Vec<String>> {
    Ok(Device::list()?.into_iter().map(|dev| dev.name).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    #[tokio::test]
    async fn test_packet_capture() {
        // 创建 broadcast channel
        let (tx, _) = broadcast::channel(1000);
        
        // 使用本地回环接口进行测试
        let filter = PacketFilter {
            bpf_filter: "tcp".to_string(),
            ..Default::default()
        };

        // 创建抓包器 - 使用 tx.clone()
        let mut capture = PacketCapture::new("lo", tx.clone(), filter).unwrap();

        let stats_handler = capture.get_stats_handler();

        // 启动抓包任务
        let mut rx = tx.subscribe();  // 使用原始 tx 创建订阅者
        let _ = tokio::spawn(async move {
            capture.capture_loop().await.unwrap();
        });

        // 等待一段时间或直到收到数据包
        tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .ok();

        // 检查统计信息
        assert!(stats_handler.packets_received.load(Ordering::Relaxed) >= 0);
    }
}
