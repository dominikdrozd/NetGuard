use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

/// In-memory DNS cache built by sniffing DNS response packets.
/// Maps IP addresses to domain names observed in DNS responses.
pub struct DnsCache {
    /// ip -> (domain, timestamp)
    cache: Arc<RwLock<HashMap<IpAddr, (String, std::time::Instant)>>>,
    /// TTL for cache entries
    ttl: std::time::Duration,
}

impl DnsCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl: std::time::Duration::from_secs(ttl_secs),
        }
    }

    /// Look up a domain for an IP address.
    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        if let Some((domain, ts)) = cache.get(ip) {
            if ts.elapsed() < self.ttl {
                return Some(domain.clone());
            }
        }
        None
    }

    /// Insert a DNS mapping (called when we sniff a DNS response).
    pub fn insert(&self, ip: IpAddr, domain: String) {
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        cache.insert(ip, (domain, std::time::Instant::now()));
    }

    /// Try to parse a DNS response packet and extract IP-to-domain mappings.
    /// DNS responses come as UDP payload from port 53.
    /// Returns the query domain name if successfully parsed.
    pub fn parse_dns_response(&self, payload: &[u8]) -> Option<String> {
        // Minimum DNS header is 12 bytes
        if payload.len() < 12 {
            return None;
        }

        // Check QR bit (bit 15 of flags) -- 1 = response
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = (flags >> 15) & 1 == 1;
        if !is_response {
            return None;
        }

        let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

        if qdcount == 0 || ancount == 0 {
            return None;
        }

        // Parse the question section to get the query domain
        let mut offset = 12;
        let domain = parse_dns_name(payload, &mut offset)?;

        // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
        offset += 4;

        // Parse answer records
        for _ in 0..ancount.min(20) {
            if offset >= payload.len() {
                break;
            }

            // Parse name (might be a pointer)
            let _name = parse_dns_name(payload, &mut offset)?;

            if offset + 10 > payload.len() {
                break;
            }

            let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > payload.len() {
                break;
            }

            match rtype {
                1 if rdlength == 4 => {
                    // A record (IPv4)
                    let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        payload[offset],
                        payload[offset + 1],
                        payload[offset + 2],
                        payload[offset + 3],
                    ));
                    self.insert(ip, domain.clone());
                }
                28 if rdlength == 16 => {
                    // AAAA record (IPv6)
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&payload[offset..offset + 16]);
                    let ip = IpAddr::V6(std::net::Ipv6Addr::from(bytes));
                    self.insert(ip, domain.clone());
                }
                _ => {}
            }

            offset += rdlength;
        }

        Some(domain)
    }

    /// Perform a synchronous reverse DNS lookup (PTR record).
    /// Falls back to returning None on failure or timeout.
    pub fn reverse_lookup(ip: &IpAddr) -> Option<String> {
        use std::net::ToSocketAddrs;
        // Use the system resolver via a dummy socket address lookup
        let sockaddr = format!("{}:0", ip);
        // This is a blocking call -- only use from OS threads
        match std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::new(*ip, 0),
            std::time::Duration::from_millis(1),
        ) {
            _ => {}
        }
        // Actually, use getnameinfo-style lookup
        // Rust's stdlib doesn't expose getnameinfo directly, so we'll skip
        // reverse DNS for now and rely on the DNS sniffing cache.
        None
    }
}

/// Parse a DNS domain name from a packet, handling compression pointers.
fn parse_dns_name(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        if pos >= data.len() || jumps > 10 {
            return None;
        }

        let len = data[pos] as usize;

        if len == 0 {
            if !jumped {
                *offset = pos + 1;
            }
            break;
        }

        // Compression pointer (top 2 bits are 11)
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            if !jumped {
                *offset = pos + 2;
            }
            pos = ptr;
            jumped = true;
            jumps += 1;
            continue;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        let label = std::str::from_utf8(&data[pos..pos + len]).ok()?;
        parts.push(label.to_string());
        pos += len;
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_response_parsing() {
        // Simplified DNS response for "example.com" -> 93.184.216.34
        let mut pkt = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: response, recursion desired+available
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answers: 1
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
        ];
        // Question: example.com, type A, class IN
        pkt.extend_from_slice(&[7]); // "example" length
        pkt.extend_from_slice(b"example");
        pkt.extend_from_slice(&[3]); // "com" length
        pkt.extend_from_slice(b"com");
        pkt.push(0); // root
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN
        // Answer: pointer to question name, type A, class IN, TTL, rdlength=4, IP
        pkt.extend_from_slice(&[0xC0, 0x0C]); // name pointer to offset 12
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        pkt.extend_from_slice(&[0x00, 0x04]); // rdlength = 4
        pkt.extend_from_slice(&[93, 184, 216, 34]); // IP

        let cache = DnsCache::new(300);
        let domain = cache.parse_dns_response(&pkt);
        assert_eq!(domain, Some("example.com".to_string()));

        let resolved = cache.lookup(&"93.184.216.34".parse().unwrap());
        assert_eq!(resolved, Some("example.com".to_string()));
    }

    #[test]
    fn test_dns_query_ignored() {
        // DNS query (QR=0) should be ignored
        let pkt = vec![
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: query
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let cache = DnsCache::new(300);
        assert!(cache.parse_dns_response(&pkt).is_none());
    }
}
