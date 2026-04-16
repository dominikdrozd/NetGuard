import { useRef, useState } from 'react';
import { useConnectionStore } from '../../stores/connectionStore';
import { VerdictBadge, ProtocolBadge } from '../common/Badge';
import { appName, timeAgo, formatSize } from '../../utils/format';
import type { Connection } from '../../types';

export function LiveStream({ onSelect }: { onSelect: (id: string) => void }) {
  const connections = useConnectionStore(s => s.connections);
  const [paused, setPaused] = useState(false);
  const snapshotRef = useRef<Connection[]>([]);

  // When not paused, update the snapshot to live data
  // When paused (hovering), keep showing the frozen snapshot so items don't jump
  if (!paused) {
    snapshotRef.current = connections.slice(0, 50);
  }
  const recent = snapshotRef.current;

  if (recent.length === 0) {
    return <div className="empty-state"><div className="icon">&#128268;</div>No connections yet</div>;
  }

  return (
    <div
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      {paused && (
        <div style={{ padding: '4px 16px', fontSize: 11, color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}>
          Live updates paused while hovering
        </div>
      )}
      {recent.map(c => (
        <div key={c.id} className="stream-entry clickable" onClick={() => onSelect(c.id)}>
          <VerdictBadge verdict={c.verdict} />
          <span className="app-name truncate">{appName(c.process)}</span>
          <span className="dest text-mono">{c.request_url || (c.hostname ? `${c.hostname}:${c.dst_port}` : `${c.dst_ip}:${c.dst_port}`)}</span>
          <ProtocolBadge protocol={c.protocol} />
          <span className="time">{formatSize(c.packet_size)}</span>
          <span className="time">{timeAgo(c.timestamp)}</span>
        </div>
      ))}
    </div>
  );
}
