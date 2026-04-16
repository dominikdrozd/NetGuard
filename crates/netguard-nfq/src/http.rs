/// Parsed HTTP request info from the first data packet.
#[derive(Debug, Clone)]
pub struct HttpRequestInfo {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
}

/// Try to parse an HTTP/1.x request from transport payload.
/// Returns None if the payload is not an HTTP request.
pub fn parse_http_request(payload: &[u8]) -> Option<HttpRequestInfo> {
    let text = std::str::from_utf8(payload).ok()?;

    // First line: METHOD /path HTTP/1.x
    let first_line = text.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return None;
    }

    let method = parts[0];
    let path = parts[1];
    let version = parts[2];

    // Validate it looks like HTTP
    if !version.starts_with("HTTP/") {
        return None;
    }

    let valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"];
    if !valid_methods.contains(&method) {
        return None;
    }

    // Extract Host header
    let host = text.lines()
        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
        .map(|line| line[5..].trim().to_string());

    Some(HttpRequestInfo {
        method: method.to_string(),
        path: path.to_string(),
        host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let info = parse_http_request(payload).unwrap();
        assert_eq!(info.method, "GET");
        assert_eq!(info.path, "/index.html");
        assert_eq!(info.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_post() {
        let payload = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}";
        let info = parse_http_request(payload).unwrap();
        assert_eq!(info.method, "POST");
        assert_eq!(info.path, "/api/data");
        assert_eq!(info.host.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn test_not_http() {
        assert!(parse_http_request(b"\x16\x03\x01\x00").is_none());
        assert!(parse_http_request(b"random data").is_none());
    }
}
