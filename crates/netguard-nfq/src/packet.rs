use netguard_core::errors::NetGuardError;
use netguard_core::models::Protocol;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: Protocol,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: usize,
    pub tcp_flags: Option<u8>,
    /// Transport-layer payload bytes (after TCP/UDP header)
    pub transport_payload: Vec<u8>,
    /// Total packet size
    pub packet_size: usize,
}

/// Parse an IP packet from raw bytes (NFQUEUE delivers at IP layer, no ethernet header).
pub fn parse_ip_packet(data: &[u8]) -> Result<ParsedPacket, NetGuardError> {
    // Minimum IPv4 header is 20 bytes
    if data.len() < 20 {
        return Err(NetGuardError::PacketParse("Packet too short".into()));
    }

    let version = (data[0] >> 4) & 0xF;

    let (src_ip, dst_ip, ip_proto, header_len) = match version {
        4 => {
            let ihl = (data[0] & 0xF) as usize * 4;
            if data.len() < ihl {
                return Err(NetGuardError::PacketParse("IPv4 header truncated".into()));
            }
            let src = IpAddr::V4(std::net::Ipv4Addr::new(
                data[12], data[13], data[14], data[15],
            ));
            let dst = IpAddr::V4(std::net::Ipv4Addr::new(
                data[16], data[17], data[18], data[19],
            ));
            let proto = data[9];
            (src, dst, proto, ihl)
        }
        6 => {
            if data.len() < 40 {
                return Err(NetGuardError::PacketParse("IPv6 header truncated".into()));
            }
            let mut src_bytes = [0u8; 16];
            let mut dst_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&data[8..24]);
            dst_bytes.copy_from_slice(&data[24..40]);
            let src = IpAddr::V6(std::net::Ipv6Addr::from(src_bytes));
            let dst = IpAddr::V6(std::net::Ipv6Addr::from(dst_bytes));
            let proto = data[6]; // next header
            (src, dst, proto, 40)
        }
        _ => {
            return Err(NetGuardError::PacketParse(format!(
                "Unknown IP version: {version}"
            )));
        }
    };

    let payload_data = &data[header_len..];

    let (protocol, src_port, dst_port, tcp_flags, transport_header_len) = match ip_proto {
        6 => {
            // TCP
            if payload_data.len() >= 20 {
                let src_port = u16::from_be_bytes([payload_data[0], payload_data[1]]);
                let dst_port = u16::from_be_bytes([payload_data[2], payload_data[3]]);
                let flags = payload_data[13];
                let data_offset = ((payload_data[12] >> 4) as usize) * 4;
                (Protocol::Tcp, src_port, dst_port, Some(flags), data_offset)
            } else {
                (Protocol::Tcp, 0, 0, None, payload_data.len())
            }
        }
        17 => {
            // UDP
            if payload_data.len() >= 8 {
                let src_port = u16::from_be_bytes([payload_data[0], payload_data[1]]);
                let dst_port = u16::from_be_bytes([payload_data[2], payload_data[3]]);
                (Protocol::Udp, src_port, dst_port, None, 8)
            } else {
                (Protocol::Udp, 0, 0, None, payload_data.len())
            }
        }
        1 | 58 => (Protocol::Icmp, 0, 0, None, 0),
        n => (Protocol::Other(n), 0, 0, None, 0),
    };

    // Extract full transport payload (after TCP/UDP header)
    let transport_payload = if payload_data.len() > transport_header_len {
        let app_data = &payload_data[transport_header_len..];
        app_data.to_vec()
    } else {
        Vec::new()
    };

    Ok(ParsedPacket {
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        payload_len: data.len(),
        tcp_flags,
        transport_payload,
        packet_size: data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_syn() {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x28, // version=4, ihl=5, tos, total length
            0x00, 0x01, 0x00, 0x00, // id, flags, fragment offset
            0x40, 0x06, 0x00, 0x00, // ttl=64, proto=6 (TCP), checksum
            0xC0, 0xA8, 0x01, 0x01, // src: 192.168.1.1
            0x5D, 0xB8, 0xD8, 0x22, // dst: 93.184.216.34
        ];
        let tcp = vec![
            0xD4, 0x31, // src port 54321
            0x01, 0xBB, // dst port 443
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0xFF, 0xFF, // data offset=5, SYN flag, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ];
        packet.extend_from_slice(&tcp);

        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.src_ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.protocol, Protocol::Tcp);
        assert_eq!(parsed.src_port, 54321);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.tcp_flags, Some(0x02)); // SYN
    }

    #[test]
    fn test_parse_udp() {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x1C, // version=4, ihl=5, total length=28
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00, // proto=17 (UDP)
            0xC0, 0xA8, 0x01, 0x01, // src: 192.168.1.1
            0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
        ];
        let udp = vec![
            0xE0, 0x00, // src port 57344
            0x00, 0x35, // dst port 53
            0x00, 0x08, // length
            0x00, 0x00, // checksum
        ];
        packet.extend_from_slice(&udp);

        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.protocol, Protocol::Udp);
        assert_eq!(parsed.src_port, 57344);
        assert_eq!(parsed.dst_port, 53);
    }

    #[test]
    fn test_parse_too_short() {
        let packet = vec![0x45, 0x00];
        assert!(parse_ip_packet(&packet).is_err());
    }

    #[test]
    fn test_parse_ipv6() {
        // IPv6 header (40 bytes) + TCP header (20 bytes)
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, // version=6, traffic class, flow label
            0x00, 0x14, 0x06, 0x40, // payload length=20, next header=6 (TCP), hop limit=64
        ];
        // src: ::1
        packet.extend_from_slice(&[0; 15]);
        packet.push(1);
        // dst: ::2
        packet.extend_from_slice(&[0; 15]);
        packet.push(2);
        // TCP header
        let tcp = vec![
            0x00, 0x50, // src port 80
            0x01, 0xBB, // dst port 443
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&tcp);

        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.protocol, Protocol::Tcp);
        assert_eq!(parsed.src_port, 80);
        assert_eq!(parsed.dst_port, 443);
    }
}
