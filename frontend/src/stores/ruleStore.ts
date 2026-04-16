import { create } from 'zustand';
import type { Rule } from '../types';

interface RuleState {
  rules: Rule[];
  setRules: (rules: Rule[]) => void;
  updateRule: (rule: Rule) => void;
}

export const useRuleStore = create<RuleState>((set) => ({
  rules: [],
  setRules: (rules) => set({ rules }),
  updateRule: (rule) => set((s) => {
    const idx = s.rules.findIndex(r => r.id === rule.id);
    if (idx >= 0) {
      const updated = [...s.rules];
      updated[idx] = rule;
      return { rules: updated };
    }
    return { rules: [...s.rules, rule] };
  }),
}));
