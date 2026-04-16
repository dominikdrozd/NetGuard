import { useStatsStore } from '../../stores/statsStore';
import { basename } from '../../utils/format';

export function TopApps() {
  const topApps = useStatsStore(s => s.stats.top_apps);

  if (!topApps || topApps.length === 0) {
    return <div className="empty-state">No data yet</div>;
  }

  const max = Math.max(...topApps.map(a => a[1]));

  return (
    <>
      {topApps.map(([name, count]) => (
        <div key={name} className="top-app">
          <span className="truncate" style={{ minWidth: 120, fontSize: 13 }}>{basename(name)}</span>
          <div className="bar-container">
            <div className="bar" style={{ width: `${(count / max * 100).toFixed(0)}%` }} />
          </div>
          <span className="count">{count}</span>
        </div>
      ))}
    </>
  );
}
