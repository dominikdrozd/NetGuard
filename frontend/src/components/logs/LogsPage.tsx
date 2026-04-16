import { useEffect, useState } from 'react';
import { api } from '../../hooks/useApi';
import { VerdictBadge, ProtocolBadge } from '../common/Badge';
import { appName, formatTime } from '../../utils/format';
import { csvEsc, downloadCsv } from '../../utils/csv';
import type { Connection } from '../../types';

export function LogsPage({ onSelect }: { onSelect: (id: string) => void }) {
  const [logs, setLogs] = useState<Connection[]>([]);
  const [search, setSearch] = useState('');

  useEffect(() => {
    api<Connection[]>('/connections?limit=200&offset=0').then(setLogs).catch(() => {});
  }, []);

  const filtered = logs.filter(c => {
    if (!search) return true;
    const s = search.toLowerCase();
    return appName(c.process).toLowerCase().includes(s)
      || c.dst_ip.includes(s)
      || String(c.dst_port).includes(s)
      || (c.hostname && c.hostname.toLowerCase().includes(s));
  });

  const exportCsv = () => {
    const header = 'Time,Application,Domain,Source,Destination,Protocol,Verdict,Rule ID';
    const rows = logs.map(c => [
      csvEsc(c.timestamp), csvEsc(appName(c.process)), csvEsc(c.hostname || ''),
      csvEsc(`${c.src_ip}:${c.src_port}`), csvEsc(`${c.dst_ip}:${c.dst_port}`),
      csvEsc(c.protocol), csvEsc(c.verdict), csvEsc(c.rule_id || ''),
    ].join(','));
    downloadCsv(`netguard-logs-${new Date().toISOString().slice(0, 10)}.csv`, header, rows);
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2>Connection History</h2>
        <div className="filters">
          <input type="text" placeholder="Search..." value={search} onChange={e => setSearch(e.target.value)} />
          <button className="btn" onClick={exportCsv}>Export CSV</button>
        </div>
      </div>
      <div className="card-body-full">
        <table>
          <thead><tr><th>Time</th><th>Application</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Verdict</th><th>Rule</th></tr></thead>
          <tbody>
            {filtered.map(c => (
              <tr key={c.id} className="clickable" onClick={() => onSelect(c.id)}>
                <td className="text-mono">{formatTime(c.timestamp)}</td>
                <td className="truncate">{appName(c.process)}</td>
                <td className="text-mono">{c.src_ip}:{c.src_port}</td>
                <td className="text-mono">{c.dst_ip}:{c.dst_port}</td>
                <td><ProtocolBadge protocol={c.protocol} /></td>
                <td><VerdictBadge verdict={c.verdict} /></td>
                <td className="text-mono" style={{ fontSize: 11 }}>{c.rule_id ? c.rule_id.substring(0, 8) + '...' : '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
