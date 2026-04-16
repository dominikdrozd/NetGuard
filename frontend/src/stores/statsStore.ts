import { create } from 'zustand';
import type { DashboardStats } from '../types';

interface StatsState {
  stats: DashboardStats;
  setStats: (s: DashboardStats) => void;
}

export const useStatsStore = create<StatsState>((set) => ({
  stats: { active_connections: 0, total_allowed: 0, total_denied: 0, connections_per_second: 0, top_apps: [] },
  setStats: (stats) => set({ stats }),
}));
