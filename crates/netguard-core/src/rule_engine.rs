use crate::errors::NetGuardError;
use crate::models::*;
use chrono::Utc;
use ipnet::IpNet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct RuleEngine {
    rules: Vec<Rule>,
    rules_path: PathBuf,
    pub default_verdict: Verdict,
}

impl RuleEngine {
    pub fn new(rules_path: PathBuf, default_verdict: Verdict) -> Self {
        Self {
            rules: Vec::new(),
            rules_path,
            default_verdict,
        }
    }

    pub fn load(path: &Path, default_verdict: Verdict) -> Result<Self, NetGuardError> {
        let rules_path = path.to_path_buf();
        if !path.exists() {
            return Ok(Self {
                rules: Vec::new(),
                rules_path,
                default_verdict,
            });
        }
        let content = std::fs::read_to_string(path)?;
        let rules_file: RulesFile = serde_json::from_str(&content)?;
        Ok(Self {
            rules: rules_file.rules,
            rules_path,
            default_verdict,
        })
    }

    pub fn save(&self) -> Result<(), NetGuardError> {
        if let Some(parent) = self.rules_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let rules_file = RulesFile {
            version: 1,
            rules: self.rules.clone(),
        };
        let content = serde_json::to_string_pretty(&rules_file)?;
        // Atomic write: write to temp file then rename
        let tmp_path = self.rules_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &content)?;
        std::fs::rename(&tmp_path, &self.rules_path)?;
        Ok(())
    }

    pub fn evaluate(&mut self, conn: &Connection) -> Option<(Uuid, Verdict)> {
        self.cleanup_expired();

        let exe_path = conn.process.as_ref().map(|p| p.exe_path.as_str());

        for rule in &mut self.rules {
            if !rule.enabled {
                continue;
            }

            if rule.temporary {
                if let Some(expires_at) = rule.expires_at {
                    if Utc::now() > expires_at {
                        continue;
                    }
                }
            }

            // Match app path
            if let Some(exe) = exe_path {
                if !match_app_path(&rule.app_path, exe) {
                    continue;
                }
            } else {
                // No process info - only match rules with wildcard app_path
                if rule.app_path != "*" {
                    continue;
                }
            }

            // Match direction
            if let Some(ref dir) = rule.direction {
                if *dir != conn.direction {
                    continue;
                }
            }

            // Match protocol
            if let Some(ref proto) = rule.protocol {
                if *proto != conn.protocol {
                    continue;
                }
            }

            // Match remote host
            if let Some(ref host_pattern) = rule.remote_host {
                if !match_remote_host(host_pattern, conn.dst_ip, conn.hostname.as_deref()) {
                    continue;
                }
            }

            // Match remote port
            if let Some(port) = rule.remote_port {
                if port != conn.dst_port {
                    continue;
                }
            }

            // All criteria matched
            rule.hit_count += 1;
            rule.last_hit = Some(Utc::now());
            return Some((rule.id, rule.verdict));
        }

        None
    }

    pub fn add_rule(&mut self, rule: Rule) -> Result<(), NetGuardError> {
        self.rules.push(rule);
        self.save()
    }

    pub fn update_rule(
        &mut self,
        id: Uuid,
        update: UpdateRuleRequest,
    ) -> Result<(), NetGuardError> {
        let rule = self
            .rules
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(NetGuardError::RuleNotFound(id))?;

        if let Some(enabled) = update.enabled {
            rule.enabled = enabled;
        }
        if let Some(app_path) = update.app_path {
            rule.app_path = app_path;
        }
        if let Some(direction) = update.direction {
            rule.direction = direction;
        }
        if let Some(remote_host) = update.remote_host {
            rule.remote_host = remote_host;
        }
        if let Some(remote_port) = update.remote_port {
            rule.remote_port = remote_port;
        }
        if let Some(protocol) = update.protocol {
            rule.protocol = protocol;
        }
        if let Some(verdict) = update.verdict {
            rule.verdict = verdict;
        }
        if let Some(note) = update.note {
            rule.note = note;
        }

        self.save()
    }

    pub fn delete_rule(&mut self, id: Uuid) -> Result<(), NetGuardError> {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        if self.rules.len() == len_before {
            return Err(NetGuardError::RuleNotFound(id));
        }
        self.save()
    }

    pub fn toggle_rule(&mut self, id: Uuid) -> Result<bool, NetGuardError> {
        let rule = self
            .rules
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(NetGuardError::RuleNotFound(id))?;
        rule.enabled = !rule.enabled;
        let new_state = rule.enabled;
        self.save()?;
        Ok(new_state)
    }

    pub fn reorder_rules(&mut self, order: &[Uuid]) -> Result<(), NetGuardError> {
        let mut reordered = Vec::with_capacity(self.rules.len());
        for id in order {
            if let Some(pos) = self.rules.iter().position(|r| r.id == *id) {
                reordered.push(self.rules.remove(pos));
            }
        }
        // Append any rules not in the order list at the end
        reordered.append(&mut self.rules);
        self.rules = reordered;
        self.save()
    }

    pub fn get_rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn get_rule(&self, id: Uuid) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn cleanup_expired(&mut self) {
        let before = self.rules.len();
        let now = Utc::now();
        self.rules.retain(|r| {
            if r.temporary {
                if let Some(expires_at) = r.expires_at {
                    return now <= expires_at;
                }
            }
            true
        });
        // Persist if any rules were removed
        if self.rules.len() < before {
            if let Err(e) = self.save() {
                tracing::warn!("Failed to save after cleaning expired rules: {e}");
            }
        }
    }

    pub fn create_rule_from_prompt(
        &mut self,
        connection: &Connection,
        response: &PromptResponse,
    ) -> Option<Rule> {
        if !response.remember {
            return None;
        }

        let exe_path = connection
            .process
            .as_ref()
            .map(|p| p.exe_path.clone())
            .unwrap_or_else(|| "*".to_string());

        let (remote_host, remote_port) = match response.scope {
            RuleScope::ThisConnectionOnly => {
                return None; // No persistent rule
            }
            RuleScope::AppToDestination => (Some(connection.dst_ip.to_string()), None),
            RuleScope::AppToPort => (None, Some(connection.dst_port)),
            RuleScope::AppAnywhere => (None, None),
        };

        let rule = Rule {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            enabled: true,
            app_path: exe_path,
            direction: Some(connection.direction),
            remote_host,
            remote_port,
            protocol: Some(connection.protocol),
            verdict: response.verdict,
            temporary: false,
            expires_at: None,
            hit_count: 0,
            last_hit: None,
            note: Some(format!(
                "Auto-created from prompt for {}",
                connection
                    .process
                    .as_ref()
                    .map(|p| p.exe_path.as_str())
                    .unwrap_or("unknown")
            )),
        };

        if let Err(e) = self.add_rule(rule.clone()) {
            tracing::error!("Failed to save rule from prompt: {e}");
            return None;
        }

        Some(rule)
    }
}

pub fn match_app_path(pattern: &str, exe_path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.contains('*') || pattern.contains('?') {
        glob::Pattern::new(pattern)
            .map(|p| p.matches(exe_path))
            .unwrap_or(false)
    } else {
        pattern == exe_path
    }
}

fn match_remote_host(pattern: &str, dst_ip: IpAddr, hostname: Option<&str>) -> bool {
    // Try as exact IP
    if let Ok(ip) = pattern.parse::<IpAddr>() {
        return ip == dst_ip;
    }

    // Try as CIDR
    if let Ok(net) = pattern.parse::<IpNet>() {
        return net.contains(&dst_ip);
    }

    // Try as hostname pattern (glob)
    if let Some(host) = hostname {
        if pattern.contains('*') || pattern.contains('?') {
            return glob::Pattern::new(pattern)
                .map(|p| p.matches(host))
                .unwrap_or(false);
        }
        return pattern == host;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::net::Ipv4Addr;
    use tempfile::NamedTempFile;

    fn make_connection(exe: &str, dst_ip: &str, dst_port: u16, proto: Protocol) -> Connection {
        Connection {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: proto,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            src_port: 54321,
            dst_ip: dst_ip.parse().unwrap(),
            dst_port,
            process: Some(ProcessInfo {
                pid: 1234,
                exe_path: exe.to_string(),
                cmdline: exe.to_string(),
                uid: 1000,
                username: "testuser".to_string(),
            }),
            verdict: Verdict::Pending,
            rule_id: None,
            direction: Direction::Outbound,
            hostname: None,
            http_method: None,
            request_url: None,
            payload_hex: None,
            packet_size: 0,
            decrypted_request_headers: None,
            decrypted_request_body: None,
            decrypted_response_status: None,
            decrypted_response_headers: None,
            decrypted_response_body: None,
        }
    }

    fn make_rule(app_path: &str, verdict: Verdict) -> Rule {
        Rule {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            enabled: true,
            app_path: app_path.to_string(),
            direction: None,
            remote_host: None,
            remote_port: None,
            protocol: None,
            verdict,
            temporary: false,
            expires_at: None,
            hit_count: 0,
            last_hit: None,
            note: None,
        }
    }

    #[test]
    fn test_exact_app_path_match() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        engine
            .rules
            .push(make_rule("/usr/bin/curl", Verdict::Allow));

        let conn = make_connection("/usr/bin/curl", "93.184.216.34", 443, Protocol::Tcp);
        let result = engine.evaluate(&conn);
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, Verdict::Allow);
    }

    #[test]
    fn test_no_match_different_app() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        engine
            .rules
            .push(make_rule("/usr/bin/curl", Verdict::Allow));

        let conn = make_connection("/usr/bin/wget", "93.184.216.34", 443, Protocol::Tcp);
        let result = engine.evaluate(&conn);
        assert!(result.is_none());
    }

    #[test]
    fn test_glob_app_path() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        engine
            .rules
            .push(make_rule("/usr/lib/firefox/*", Verdict::Allow));

        let conn = make_connection(
            "/usr/lib/firefox/firefox-bin",
            "93.184.216.34",
            443,
            Protocol::Tcp,
        );
        let result = engine.evaluate(&conn);
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, Verdict::Allow);
    }

    #[test]
    fn test_wildcard_matches_all() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        engine.rules.push(make_rule("*", Verdict::Deny));

        let conn = make_connection("/usr/bin/anything", "1.2.3.4", 80, Protocol::Tcp);
        let result = engine.evaluate(&conn);
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, Verdict::Deny);
    }

    #[test]
    fn test_port_filter() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        let mut rule = make_rule("/usr/bin/curl", Verdict::Allow);
        rule.remote_port = Some(443);
        engine.rules.push(rule);

        // Port 443 should match
        let conn443 = make_connection("/usr/bin/curl", "1.2.3.4", 443, Protocol::Tcp);
        assert!(engine.evaluate(&conn443).is_some());

        // Port 80 should not match
        let conn80 = make_connection("/usr/bin/curl", "1.2.3.4", 80, Protocol::Tcp);
        assert!(engine.evaluate(&conn80).is_none());
    }

    #[test]
    fn test_cidr_match() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        let mut rule = make_rule("*", Verdict::Deny);
        rule.remote_host = Some("10.0.0.0/8".to_string());
        engine.rules.push(rule);

        let conn_in = make_connection("/usr/bin/curl", "10.1.2.3", 80, Protocol::Tcp);
        assert!(engine.evaluate(&conn_in).is_some());

        let conn_out = make_connection("/usr/bin/curl", "8.8.8.8", 80, Protocol::Tcp);
        assert!(engine.evaluate(&conn_out).is_none());
    }

    #[test]
    fn test_protocol_filter() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        let mut rule = make_rule("*", Verdict::Allow);
        rule.protocol = Some(Protocol::Tcp);
        engine.rules.push(rule);

        let tcp_conn = make_connection("/usr/bin/curl", "1.2.3.4", 80, Protocol::Tcp);
        assert!(engine.evaluate(&tcp_conn).is_some());

        let udp_conn = make_connection("/usr/bin/curl", "1.2.3.4", 53, Protocol::Udp);
        assert!(engine.evaluate(&udp_conn).is_none());
    }

    #[test]
    fn test_direction_filter() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        let mut rule = make_rule("*", Verdict::Allow);
        rule.direction = Some(Direction::Outbound);
        engine.rules.push(rule);

        let mut conn = make_connection("/usr/bin/curl", "1.2.3.4", 80, Protocol::Tcp);
        assert!(engine.evaluate(&conn).is_some());

        conn.direction = Direction::Inbound;
        assert!(engine.evaluate(&conn).is_none());
    }

    #[test]
    fn test_first_match_wins() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        engine.rules.push(make_rule("/usr/bin/curl", Verdict::Deny));
        engine.rules.push(make_rule("*", Verdict::Allow));

        let conn = make_connection("/usr/bin/curl", "1.2.3.4", 80, Protocol::Tcp);
        let result = engine.evaluate(&conn);
        assert_eq!(result.unwrap().1, Verdict::Deny);
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        let mut rule = make_rule("/usr/bin/curl", Verdict::Deny);
        rule.enabled = false;
        engine.rules.push(rule);

        let conn = make_connection("/usr/bin/curl", "1.2.3.4", 80, Protocol::Tcp);
        assert!(engine.evaluate(&conn).is_none());
    }

    #[test]
    fn test_expired_temporary_rule_skipped() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        let mut rule = make_rule("/usr/bin/curl", Verdict::Allow);
        rule.temporary = true;
        rule.expires_at = Some(Utc::now() - Duration::hours(1));
        engine.rules.push(rule);

        let conn = make_connection("/usr/bin/curl", "1.2.3.4", 80, Protocol::Tcp);
        assert!(engine.evaluate(&conn).is_none());
    }

    #[test]
    fn test_hit_count_increments() {
        let tmp = NamedTempFile::new().unwrap();
        let mut engine = RuleEngine::new(tmp.path().to_path_buf(), Verdict::Deny);
        engine
            .rules
            .push(make_rule("/usr/bin/curl", Verdict::Allow));

        let conn = make_connection("/usr/bin/curl", "1.2.3.4", 80, Protocol::Tcp);
        engine.evaluate(&conn);
        engine.evaluate(&conn);
        engine.evaluate(&conn);

        assert_eq!(engine.rules[0].hit_count, 3);
        assert!(engine.rules[0].last_hit.is_some());
    }

    #[test]
    fn test_save_and_load() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let mut engine = RuleEngine::new(path.clone(), Verdict::Deny);
        engine
            .rules
            .push(make_rule("/usr/bin/curl", Verdict::Allow));
        engine.save().unwrap();

        let loaded = RuleEngine::load(&path, Verdict::Deny).unwrap();
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].app_path, "/usr/bin/curl");
        assert_eq!(loaded.rules[0].verdict, Verdict::Allow);
    }

    #[test]
    fn test_match_remote_host_exact_ip() {
        assert!(match_remote_host(
            "1.2.3.4",
            "1.2.3.4".parse().unwrap(),
            None
        ));
        assert!(!match_remote_host(
            "1.2.3.4",
            "5.6.7.8".parse().unwrap(),
            None
        ));
    }

    #[test]
    fn test_match_remote_host_hostname() {
        assert!(match_remote_host(
            "*.example.com",
            "1.2.3.4".parse().unwrap(),
            Some("api.example.com")
        ));
        assert!(!match_remote_host(
            "*.example.com",
            "1.2.3.4".parse().unwrap(),
            Some("api.other.com")
        ));
    }
}
