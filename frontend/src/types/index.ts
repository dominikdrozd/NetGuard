export type Protocol = 'tcp' | 'udp' | 'icmp' | { other: number };
export type Direction = 'outbound' | 'inbound';
export type Verdict = 'allow' | 'deny' | 'pending';
export type RuleScope = 'this_connection_only' | 'app_to_destination' | 'app_to_port' | 'app_anywhere';

export interface ProcessInfo {
  pid: number;
  exe_path: string;
  cmdline: string;
  uid: number;
  username: string;
}

export interface Connection {
  id: string;
  timestamp: string;
  protocol: Protocol;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  process: ProcessInfo | null;
  verdict: Verdict;
  rule_id: string | null;
  direction: Direction;
  hostname: string | null;
  payload_hex?: string;
  packet_size: number;
}

export interface Rule {
  id: string;
  created_at: string;
  enabled: boolean;
  app_path: string;
  direction: Direction | null;
  remote_host: string | null;
  remote_port: number | null;
  protocol: Protocol | null;
  verdict: Verdict;
  temporary: boolean;
  expires_at: string | null;
  hit_count: number;
  last_hit: string | null;
  note: string | null;
}

export interface PendingPrompt {
  id: string;
  connection: Connection;
  created_at: string;
}

export interface PromptResponse {
  prompt_id: string;
  verdict: Verdict;
  remember: boolean;
  scope: RuleScope;
}

export interface DashboardStats {
  active_connections: number;
  total_allowed: number;
  total_denied: number;
  connections_per_second: number;
  top_apps: [string, number][];
}

export type WsEvent =
  | { type: 'new_connection'; data: Connection }
  | { type: 'prompt'; data: PendingPrompt }
  | { type: 'prompt_resolved'; data: { prompt_id: string; verdict: Verdict } }
  | { type: 'rule_changed'; data: Rule }
  | { type: 'stats'; data: DashboardStats };

export interface CreateRuleRequest {
  app_path: string;
  direction?: Direction | null;
  remote_host?: string | null;
  remote_port?: number | null;
  protocol?: Protocol | null;
  verdict: Verdict;
  temporary: boolean;
  duration_secs?: number | null;
  note?: string | null;
}

export interface UpdateRuleRequest {
  enabled?: boolean;
  app_path?: string;
  direction?: Direction | null;
  remote_host?: string | null;
  remote_port?: number | null;
  protocol?: Protocol | null;
  verdict?: Verdict;
  note?: string | null;
}
