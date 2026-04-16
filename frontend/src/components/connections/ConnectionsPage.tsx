import { useEffect, useState, useRef } from 'react';
import { api } from '../../hooks/useApi';
import { useConnectionStore } from '../../stores/connectionStore';
import { VerdictBadge, ProtocolBadge } from '../common/Badge';
import { appName, formatTime, formatSize, protocolStr } from '../../utils/format';
import type { Connection } from '../../types';

export function ConnectionsPage({ onSelect }: { onSelect: (id: string) => void }) {
  const connections = useConnectionStore(s => s.connections);
  const setConnections = useConnectionStore(s => s.setConnections);
  const appendConnections = useConnectionStore(s => s.appendConnections);
  const [offset, setOffset] = useState(0);
  const [appFilter, setAppFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');
  const [protoFilter, setProtoFilter] = useState('');
  const [paused, setPaused] = useState(false);
  const snapshotRef = useRef<Connection[]>([]);

  useEffect(() => {
    api<Connection[]>('/connections?limit=50&offset=0').then(setConnections).catch(() => {});
  }, [setConnections]);

  // Freeze the displayed list while hovering to prevent jump
  if (!paused) {
    snapshotRef.current = connections;
  }
  const displayConnections = snapshotRef.current;

  const loadMore = () => {
    const next = offset + 50;
    api<Connection[]>(`/connections?limit=50&offset=${next}`).then(data => {
      appendConnections(data);
      setOffset(next);
    }).catch(() => {});
  };

  const filtered = displayConnections.filter(c => {
    if (appFilter && !appName(c.process).toLowerCase().includes(appFilter.toLowerCase())) return false;
    if (verdictFilter && c.verdict !== verdictFilter) return false;
    if (protoFilter && protocolStr(c.protocol) !== protoFilter) return false;
    return true;
  });

  return (
    <div className="card">
      <div className="card-header">
        <h2>All Connections</h2>
        <div className="filters">
          <input type="text" placeholder="Filter by app..." value={appFilter} onChange={e => setAppFilter(e.target.value)} />
          <select value={verdictFilter} onChange={e => setVerdictFilter(e.target.value)}>
            <option value="">All verdicts</option>
            <option value="allow">Allowed</option>
            <option value="deny">Denied</option>
          </select>
          <select value={protoFilter} onChange={e => setProtoFilter(e.target.value)}>
            <option value="">All protocols</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
          {paused && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Updates paused</span>}
        </div>
      </div>
      <div
        className="card-body-full"
        onMouseEnter={() => setPaused(true)}
        onMouseLeave={() => setPaused(false)}
      >
        <table>
          <thead>
            <tr>
              <th>Time</th><th>Application</th><th>Domain</th><th>Destination</th>
              <th>Port</th><th>Protocol</th><th>Size</th><th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(c => (
              <tr key={c.id} className="clickable" onClick={() => onSelect(c.id)}>
                <td className="text-mono">{formatTime(c.timestamp)}</td>
                <td className="truncate">{appName(c.process)}</td>
                <td className="domain-label truncate">{c.request_url || c.hostname || '-'}</td>
                <td className="text-mono">{c.dst_ip}</td>
                <td className="text-mono">{c.dst_port}</td>
                <td><ProtocolBadge protocol={c.protocol} /></td>
                <td>{formatSize(c.packet_size)}</td>
                <td><VerdictBadge verdict={c.verdict} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div style={{ textAlign: 'center', padding: 12 }}>
        <button className="btn" onClick={loadMore}>Load More</button>
      </div>
    </div>
  );
}
