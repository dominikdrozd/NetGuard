import { useStatsStore } from '../../stores/statsStore';

export function StatsGrid() {
  const stats = useStatsStore(s => s.stats);
  return (
    <div className="stats-grid">
      <div className="stat-card"><div className="label">Active Connections</div><div className="value accent">{stats.active_connections}</div></div>
      <div className="stat-card"><div className="label">Total Allowed</div><div className="value green">{stats.total_allowed}</div></div>
      <div className="stat-card"><div className="label">Total Denied</div><div className="value red">{stats.total_denied}</div></div>
      <div className="stat-card"><div className="label">Conn/sec</div><div className="value">{stats.connections_per_second.toFixed(1)}</div></div>
    </div>
  );
}
