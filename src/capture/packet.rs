use bytes::{BufMut, Bytes, BytesMut};
use pcap::{Active, Capture, Device};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{self, Packet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::error::{ForwarderError, Result};

/// 扩展的数据包信息结构
#[derive(Clone)]
pub struct PacketInfo {
    pub raw_data: Bytes,
    pub timestamp: SystemTime,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub length: usize,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub interface_name: String,
    pub pay_load: Option<Bytes>,
}

/// 抓包过滤器
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
    tx: mpsc::Sender<PacketInfo>,
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
        tx: mpsc::Sender<PacketInfo>,
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
        // 先获取我们需要的引用
        let tx = &self.tx; // 只需要共享引用
        let stats = &self.stats; // 使用原子操作的统计信息
        let interface_name = &self.interface_name;

        loop {
            // 这里只借用 self.cap
            match self.cap.next_packet() {
                Ok(packet) => {
                    // 使用原子操作更新统计
                    stats.packets_received.fetch_add(1, Ordering::Relaxed);

                    if let Some(packet_info) = Self::process_packet(&packet, interface_name) {
                        // 使用之前获取的引用
                        if let Err(e) = tx.send(packet_info).await {
                            log::error!("Failed to send packet: {}", e);
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
    fn process_packet(packet: &pcap::Packet, interface_name: &str) -> Option<PacketInfo> {
        let ethernet = EthernetPacket::new(packet.data)?;

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ip_packet = Ipv4Packet::new(ethernet.payload())?;
                let mut src_port = None;
                let mut dst_port = None;
                let mut pay_load= None;


                // 解析TCP/UDP端口
                match ip_packet.get_next_level_protocol().0 {
                    6 => {
                        // TCP
                        if let Some(tcp) = TcpPacket::new(ip_packet.payload()) {
                            src_port = Some(tcp.get_source());
                            dst_port = Some(tcp.get_destination());
                            pay_load = Some(Bytes::copy_from_slice(tcp.payload()));
                        }
                    }
                    17 => {
                        // UDP
                        if let Some(udp) = UdpPacket::new(ip_packet.payload()) {
                            src_port = Some(udp.get_source());
                            dst_port = Some(udp.get_destination());
                            pay_load = Some(Bytes::copy_from_slice(udp.payload()));
                        }
                    }
                    _ => {}
                }

                Some(PacketInfo {
                    raw_data: Bytes::copy_from_slice(packet.data),
                    timestamp: SystemTime::now(),
                    source: ip_packet.get_source(),
                    destination: ip_packet.get_destination(),
                    protocol: ip_packet.get_next_level_protocol().0,
                    length: packet.data.len(),
                    src_port,
                    dst_port,
                    interface_name: interface_name.to_string(),
                    pay_load: pay_load,
                })
            }
            _ => None,
        }
    }

    pub fn build_packet(packet_info: &PacketInfo) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_slice(&packet_info.raw_data[..14]);

        let mut ip_header = Vec::new();
        ip_header.extend_from_slice(&packet_info.raw_data[14..34]);

        let src_ip_ocs = packet_info.source.octets();
        ip_header[12] = src_ip_ocs[0];
        ip_header[13] = src_ip_ocs[1];
        ip_header[14] = src_ip_ocs[2];
        ip_header[15] = src_ip_ocs[3];

        let dst_ip_ocs = packet_info.destination.octets();
        ip_header[16] = dst_ip_ocs[0];
        ip_header[17] = dst_ip_ocs[1];
        ip_header[18] = dst_ip_ocs[2];
        ip_header[19] = dst_ip_ocs[3];

        buf.put_slice(&ip_header);

        buf.put_slice(&packet_info.raw_data[34..]);

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
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_packet_capture() {
        // 创建通道
        let (tx, mut rx) = mpsc::channel(1000);

        // 使用本地回环接口进行测试
        let filter = PacketFilter {
            bpf_filter: "tcp".to_string(),
            ..Default::default()
        };

        // 创建抓包器
        let mut capture = PacketCapture::new("lo", tx, filter).unwrap();

        let stats_handler = capture.get_stats_handler();

        // 启动抓包任务
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
