import { create } from 'zustand';
import type { Connection, EnrichmentDelta } from '../types';

interface ConnectionState {
  connections: Connection[];
  addConnection: (c: Connection) => void;
  setConnections: (conns: Connection[]) => void;
  appendConnections: (conns: Connection[]) => void;
  enrichConnection: (id: string, fields: EnrichmentDelta) => void;
}

export const useConnectionStore = create<ConnectionState>((set) => ({
  connections: [],

  addConnection: (c) => set((s) => {
    const updated = [c, ...s.connections];
    if (updated.length > 500) updated.pop();
    return { connections: updated };
  }),

  setConnections: (connections) => set({ connections }),

  appendConnections: (conns) => set((s) => ({
    connections: [...s.connections, ...conns],
  })),

  enrichConnection: (id, fields) => set((s) => ({
    connections: s.connections.map(c => c.id === id ? { ...c, ...fields } : c),
  })),
}));
