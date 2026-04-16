import { useState } from 'react';
import { useConnectionStore } from '../../stores/connectionStore';
import { ModalBackdrop } from '../common/ModalBackdrop';
import { VerdictBadge, ProtocolBadge } from '../common/Badge';
import { formatDateTime, formatSize, protocolStr } from '../../utils/format';
import { hexToAsciiLines } from '../../utils/hex';
import { api } from '../../hooks/useApi';
import type { CreateRuleRequest, Verdict, Direction, Protocol } from '../../types';

interface Props {
  connectionId: string | null;
  onClose: () => void;
}

export function PacketDetailModal({ connectionId, onClose }: Props) {
  const connections = useConnectionStore(s => s.connections);
  const c = connectionId ? connections.find(x => x.id === connectionId) : null;
  const [ruleCreated, setRuleCreated] = useState<'allow' | 'deny' | null>(null);

  const createRule = async (verdict: Verdict) => {
    if (!c) return;
    const req: CreateRuleRequest = {
      app_path: c.process?.exe_path || '*',
      remote_host: c.dst_ip,
      remote_port: null,
      protocol: (typeof c.protocol === 'string' ? c.protocol : null) as Protocol | null,
      direction: c.direction as Direction,
      verdict,
      temporary: false,
      note: `Created from connection detail: ${c.process?.exe_path || 'unknown'} -> ${c.hostname || c.dst_ip}:${c.dst_port}`,
    };
    try {
      await api('/rules', { method: 'POST', body: JSON.stringify(req) });
      setRuleCreated(verdict);
    } catch (e: any) {
      alert('Failed to create rule: ' + e.message);
    }
  };

  const handleClose = () => {
    setRuleCreated(null);
    onClose();
  };

  return (
    <ModalBackdrop open={!!c} onClose={handleClose} width="640px">
      {c && (
        <>
          <h2>Connection Detail</h2>
          <Row label="Time" value={formatDateTime(c.timestamp)} />
          <Row label="Application" value={c.process ? c.process.exe_path : 'unknown'} />
          <Row label="Command" value={c.process ? c.process.cmdline : '-'} />
          <Row label="PID / User" value={c.process ? `${c.process.pid} / ${c.process.username || c.process.uid}` : '-'} />
          <Row label="Domain" value={c.hostname || 'not resolved'} className="domain-label" />
          <Row label="Direction" value={c.direction} />
          <Row label="Source" value={`${c.src_ip}:${c.src_port}`} mono />
          <Row label="Destination" value={`${c.dst_ip}:${c.dst_port}`} mono />
          <div className="pkt-row">
            <span className="pkt-label">Protocol</span>
            <span className="pkt-value"><ProtocolBadge protocol={c.protocol} /></span>
          </div>
          <Row label="Packet Size" value={formatSize(c.packet_size)} />
          <div className="pkt-row">
            <span className="pkt-label">Verdict</span>
            <span className="pkt-value"><VerdictBadge verdict={c.verdict} /></span>
          </div>
          <Row label="Rule ID" value={c.rule_id || 'none'} mono />
          <div style={{ marginTop: 12 }}>
            <div className="pkt-label" style={{ marginBottom: 6 }}>Payload (hex + ASCII)</div>
            <pre className="hex-dump">{c.payload_hex ? hexToAsciiLines(c.payload_hex) : 'No payload data'}</pre>
          </div>

          {ruleCreated ? (
            <div style={{ marginTop: 16, padding: '10px 14px', borderRadius: 6, background: ruleCreated === 'allow' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)', border: `1px solid ${ruleCreated === 'allow' ? 'var(--green)' : 'var(--red)'}` }}>
              Rule created: <strong>{ruleCreated === 'allow' ? 'Allow' : 'Deny'}</strong> {c.process?.exe_path || '*'} to {c.hostname || c.dst_ip}
            </div>
          ) : (
            <div style={{ marginTop: 16, padding: '12px 0', borderTop: '1px solid var(--border)', display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: 13, marginRight: 8 }}>Create rule for this app + destination:</span>
              <button className="btn btn-sm btn-success" onClick={() => createRule('allow')}>Allow</button>
              <button className="btn btn-sm btn-deny" onClick={() => createRule('deny')}>Block</button>
            </div>
          )}

          <div className="form-actions">
            <button className="btn" onClick={handleClose}>Close</button>
          </div>
        </>
      )}
    </ModalBackdrop>
  );
}

function Row({ label, value, mono, className }: { label: string; value: string; mono?: boolean; className?: string }) {
  return (
    <div className="pkt-row">
      <span className="pkt-label">{label}</span>
      <span className={`pkt-value ${mono ? 'text-mono' : ''} ${className || ''}`}>{value}</span>
    </div>
  );
}
