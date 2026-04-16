import { create } from 'zustand';
import type { PendingPrompt } from '../types';

interface PromptState {
  prompts: Record<string, PendingPrompt>;
  addPrompt: (p: PendingPrompt) => void;
  removePrompt: (id: string) => void;
  setPrompts: (list: PendingPrompt[]) => void;
}

export const usePromptStore = create<PromptState>((set) => ({
  prompts: {},
  addPrompt: (p) => set((s) => ({ prompts: { ...s.prompts, [p.id]: p } })),
  removePrompt: (id) => set((s) => {
    const { [id]: _, ...rest } = s.prompts;
    return { prompts: rest };
  }),
  setPrompts: (list) => set({
    prompts: Object.fromEntries(list.map(p => [p.id, p])),
  }),
}));
