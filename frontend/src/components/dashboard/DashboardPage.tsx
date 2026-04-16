import { useEffect } from 'react';
import { api } from '../../hooks/useApi';
import { useStatsStore } from '../../stores/statsStore';
import { StatsGrid } from './StatsGrid';
import { LiveStream } from './LiveStream';
import { TopApps } from './TopApps';
import type { DashboardStats } from '../../types';

export function DashboardPage({ onSelectConnection }: { onSelectConnection: (id: string) => void }) {
  const setStats = useStatsStore(s => s.setStats);

  useEffect(() => {
    const refresh = () => {
      api<DashboardStats>('/stats').then(setStats).catch(() => {});
    };
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, [setStats]);

  return (
    <>
      <StatsGrid />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="card">
          <div className="card-header"><h2>Live Connections</h2></div>
          <div className="card-body"><LiveStream onSelect={onSelectConnection} /></div>
        </div>
        <div className="card">
          <div className="card-header"><h2>Top Applications</h2></div>
          <div className="card-body p-16"><TopApps /></div>
        </div>
      </div>
    </>
  );
}
