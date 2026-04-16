import { create } from 'zustand';

type WsStatus = 'connecting' | 'connected' | 'disconnected';

interface WsState {
  status: WsStatus;
  setStatus: (s: WsStatus) => void;
}

export const useWsStore = create<WsState>((set) => ({
  status: 'disconnected',
  setStatus: (status) => set({ status }),
}));
