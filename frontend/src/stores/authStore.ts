import { create } from 'zustand';

interface AuthState {
  token: string | null;
  login: (token: string) => Promise<boolean>;
  logout: () => void;
  validateExisting: () => Promise<boolean>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: sessionStorage.getItem('netguard_token'),

  login: async (token: string) => {
    const res = await fetch('/auth/validate-token', { method: 'POST', body: token });
    if (res.ok) {
      sessionStorage.setItem('netguard_token', token);
      set({ token });
      return true;
    }
    return false;
  },

  logout: () => {
    sessionStorage.removeItem('netguard_token');
    set({ token: null });
  },

  validateExisting: async () => {
    const token = get().token;
    if (!token) return false;
    try {
      const res = await fetch('/auth/validate-token', { method: 'POST', body: token });
      if (!res.ok) {
        sessionStorage.removeItem('netguard_token');
        set({ token: null });
        return false;
      }
      return true;
    } catch {
      set({ token: null });
      return false;
    }
  },
}));
