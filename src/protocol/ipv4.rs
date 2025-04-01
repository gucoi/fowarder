use crate::{error::ForwarderError, Result};
use bytes::{BufMut, BytesMut};
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    version: u8,           // 4 bits - IPv4 version
    ihl: u8,               // 4 bits - Internet Header Length
    dscp: u8,              // 6 bits - Differentiated Services Code Point
    ecn: u8,               // 2 bits - Explicit Congestion Notification
    total_length: u16,     // 16 bits - Total Length
    identification: u16,   // 16 bits - Identification
    flags: u8,             // 3 bits - Flags
    fragment_offset: u16,  // 13 bits - Fragment Offset
    ttl: u8,               // 8 bits - Time To Live
    protocol: u8,          // 8 bits - Protocol
    checksum: u16,         // 16 bits - Header Checksum
    source: Ipv4Addr,      // 32 bits - Source IP Address
    destination: Ipv4Addr, // 32 bits - Destination IP Address
    options: Vec<u8>,      // Variable length - Options (if any)
}

impl Ipv4Header {
    /// Create a new IPv4 header with default values
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self {
            version: 4,         // IPv4 version is 4
            ihl: 5,             // Minimum header length (5 * 4 = 20 bytes)
            dscp: 0,            // Default DSCP value
            ecn: 0,             // Default ECN value
            total_length: 20,   // Minimum size (will be updated when adding payload)
            identification: 0,  // Will be set by the OS/network stack
            flags: 0,           // No flags set by default
            fragment_offset: 0, // No fragmentation by default
            ttl: 64,            // Default TTL value
            protocol: 0,        // Will be set based on upper layer protocol
            checksum: 0,        // Will be calculated later
            source: src,
            destination: dst,
            options: Vec::new(), // No options by default
        }
    }

    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }

    pub fn write_to(&self, buf: &mut BytesMut) -> Result<()> {
        // First byte: Version (4 bits) and IHL (4 bits)
        buf.put_u8((self.version << 4) | (self.ihl & 0x0F));

        // Second byte: DSCP (6 bits) and ECN (2 bits)
        buf.put_u8((self.dscp << 2) | (self.ecn & 0x03));

        // Total Length (16 bits)
        buf.put_u16(self.total_length);

        // Identification (16 bits)
        buf.put_u16(self.identification);

        // Flags (3 bits) and Fragment Offset (13 bits)
        let flags_and_fragment =
            ((self.flags as u16 & 0x07) << 13) | (self.fragment_offset & 0x1FFF);
        buf.put_u16(flags_and_fragment);

        // Time to Live (8 bits)
        buf.put_u8(self.ttl);

        // Protocol (8 bits)
        buf.put_u8(self.protocol);

        // Header Checksum (16 bits)
        buf.put_u16(self.checksum);

        // Source IP Address (32 bits)
        buf.extend_from_slice(&self.source.octets());

        // Destination IP Address (32 bits)
        buf.extend_from_slice(&self.destination.octets());

        // Add options if present
        if !self.options.is_empty() {
            buf.extend_from_slice(&self.options);
        }

        // Add padding if necessary to ensure the header is a multiple of 4 bytes
        let padding_len = (4 - (buf.len() % 4)) % 4;
        for _ in 0..padding_len {
            buf.put_u8(0);
        }

        Ok(())
    }

    /// Set the protocol field (e.g., TCP = 6, UDP = 17, etc.)
    pub fn set_protocol(&mut self, protocol: u8) {
        self.protocol = protocol;
    }

    /// Set the TTL value
    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }

    /// Set the total length (header + payload)
    pub fn set_total_length(&mut self, length: u16) {
        self.total_length = length;
    }

    /// Add IP options (if any)
    pub fn add_option(&mut self, option: u8) {
        self.options.push(option);
        // Update IHL to account for options
        self.ihl = ((20 + self.options.len() + 3) / 4) as u8;
    }

    /// Calculate IPv4 header checksum
    pub fn calculate_checksum(&mut self) {
        // Reset checksum first
        self.checksum = 0;

        // Convert header to array of 16-bit words
        let mut words = Vec::new();
        words.push(
            ((self.version as u16) << 12)
                | ((self.ihl as u16) << 8)
                | ((self.dscp as u16) << 2)
                | (self.ecn as u16),
        );
        words.push(self.total_length);
        words.push(self.identification);
        words.push(((self.flags as u16) << 13) | self.fragment_offset);
        words.push(((self.ttl as u16) << 8) | (self.protocol as u16));
        words.push(self.checksum);

        // Add source IP address (as two 16-bit words)
        let src_octets = self.source.octets();
        words.push(((src_octets[0] as u16) << 8) | (src_octets[1] as u16));
        words.push(((src_octets[2] as u16) << 8) | (src_octets[3] as u16));

        // Add destination IP address (as two 16-bit words)
        let dst_octets = self.destination.octets();
        words.push(((dst_octets[0] as u16) << 8) | (dst_octets[1] as u16));
        words.push(((dst_octets[2] as u16) << 8) | (dst_octets[3] as u16));

        // Calculate checksum
        let mut sum: u32 = 0;
        for word in words {
            sum += word as u32;
        }

        // Add carry bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        self.checksum = !(sum as u16);
    }

    /// Serialize the header into a byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // First byte: Version (4 bits) + IHL (4 bits)
        bytes.push((self.version << 4) | self.ihl);

        // Second byte: DSCP (6 bits) + ECN (2 bits)
        bytes.push((self.dscp << 2) | self.ecn);

        // Total Length (2 bytes)
        bytes.extend_from_slice(&self.total_length.to_be_bytes());

        // Identification (2 bytes)
        bytes.extend_from_slice(&self.identification.to_be_bytes());

        // Flags (3 bits) + Fragment Offset (13 bits)
        let flags_frag = ((self.flags as u16) << 13) | self.fragment_offset;
        bytes.extend_from_slice(&flags_frag.to_be_bytes());

        // TTL (1 byte)
        bytes.push(self.ttl);

        // Protocol (1 byte)
        bytes.push(self.protocol);

        // Checksum (2 bytes)
        bytes.extend_from_slice(&self.checksum.to_be_bytes());

        // Source IP (4 bytes)
        bytes.extend_from_slice(&self.source.octets());

        // Destination IP (4 bytes)
        bytes.extend_from_slice(&self.destination.octets());

        // Options (if any)
        bytes.extend_from_slice(&self.options);

        bytes
    }

    /// Parse IPv4 header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 20 {
            return Err(ForwarderError::Network("Packet too short for IPv4 header".to_string()));
        }

        let version = (bytes[0] >> 4) & 0x0F;
        if version != 4 {
            return Err(ForwarderError::PacketFormat("Not an Ipv4 Packet".to_string()));
        }

        let mut header = Self {
            version: version,
            ihl: bytes[0] & 0x0F,
            dscp: bytes[1] >> 2,
            ecn: bytes[1] & 0x03,
            total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
            identification: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags: (bytes[6] >> 5) & 0x07,
            fragment_offset: u16::from_be_bytes([bytes[6] & 0x1F, bytes[7]]),
            ttl: bytes[8],
            protocol: bytes[9],
            checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
            source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
            options: Vec::new(),
        };

        // Handle options if present
        if header.ihl > 5 {
            let options_length = ((header.ihl - 5) * 4) as usize;
            if bytes.len() >= 20 + options_length {
                header.options = bytes[20..20 + options_length].to_vec();
            } else {
                return Err(ForwarderError::PacketFormat("Packet too short for declared options".to_string()));
            }
        }

        Ok(header)
    }
}

// 实现一些有用的常量
impl Ipv4Header {
    pub const VERSION: u8 = 4;
    pub const MIN_HEADER_LENGTH: u8 = 20; // 5 * 4 bytes

    // Protocol numbers
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;

    // Flags
    pub const DONT_FRAGMENT: u8 = 0x40;
    pub const MORE_FRAGMENTS: u8 = 0x20;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_header_creation() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let mut header = Ipv4Header::new(src, dst);

        assert_eq!(header.version, 4);
        assert_eq!(header.ihl, 5);
        assert_eq!(header.ttl, 64);

        // Test protocol setting
        header.set_protocol(Ipv4Header::TCP);
        assert_eq!(header.protocol, 6);

        // Test serialization and deserialization
        let bytes = header.to_bytes();
        let parsed_header = Ipv4Header::from_bytes(&bytes).unwrap();

        assert_eq!(parsed_header.source, src);
        assert_eq!(parsed_header.destination, dst);
        assert_eq!(parsed_header.protocol, Ipv4Header::TCP);
    }
}
