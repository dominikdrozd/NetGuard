/// Extract the SNI (Server Name Indication) hostname from a TLS Client Hello message.
/// The Client Hello is the first data packet sent by the client in a TLS handshake.
/// Returns None if the payload is not a TLS Client Hello or has no SNI extension.
pub fn extract_sni(payload: &[u8]) -> Option<String> {
    // TLS record: type(1) + version(2) + length(2) + handshake
    if payload.len() < 5 {
        return None;
    }

    // Content type 22 = Handshake
    if payload[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }

    let hs = &payload[5..];

    // Handshake type 1 = Client Hello
    if hs.is_empty() || hs[0] != 0x01 {
        return None;
    }

    if hs.len() < 4 {
        return None;
    }

    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len {
        return None;
    }

    let ch = &hs[4..];

    // Client Hello: version(2) + random(32) + session_id_len(1) + session_id + ...
    if ch.len() < 34 {
        return None;
    }

    let mut pos = 2 + 32; // skip version + random

    // Session ID
    if pos >= ch.len() {
        return None;
    }
    let session_id_len = ch[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > ch.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // Compression methods
    if pos >= ch.len() {
        return None;
    }
    let comp_len = ch[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    if ext_end > ch.len() {
        return None;
    }

    // Walk extensions looking for SNI (type 0x0000)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            // server_name_list_length(2) + server_name_type(1) + name_length(2) + name
            if ext_data_len >= 5 && pos + ext_data_len <= ext_end {
                let name_type = ch[pos + 2];
                let name_len = u16::from_be_bytes([ch[pos + 3], ch[pos + 4]]) as usize;
                if name_type == 0 && pos + 5 + name_len <= ext_end {
                    if let Ok(name) = std::str::from_utf8(&ch[pos + 5..pos + 5 + name_len]) {
                        return Some(name.to_string());
                    }
                }
            }
            return None;
        }

        pos += ext_data_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_tls() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(extract_sni(&[]), None);
    }
}
