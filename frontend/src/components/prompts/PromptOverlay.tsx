import { useState } from 'react';
import { usePromptStore } from '../../stores/promptStore';
import { api } from '../../hooks/useApi';
import { appName } from '../../utils/format';
import type { RuleScope, Verdict } from '../../types';

export function PromptOverlay() {
  const prompts = usePromptStore(s => s.prompts);
  const removePrompt = usePromptStore(s => s.removePrompt);
  const entries = Object.values(prompts);

  if (entries.length === 0) return null;

  const respond = async (id: string, verdict: Verdict, remember: boolean, scope: RuleScope) => {
    try {
      await api(`/prompts/${id}/respond`, {
        method: 'POST',
        body: JSON.stringify({ prompt_id: id, verdict, remember, scope }),
      });
      removePrompt(id);
    } catch {
      removePrompt(id);
    }
  };

  return (
    <div className="prompt-overlay">
      {entries.map(p => (
        <PromptCard key={p.id} prompt={p} onRespond={respond} />
      ))}
    </div>
  );
}

function PromptCard({ prompt, onRespond }: {
  prompt: { id: string; connection: any };
  onRespond: (id: string, verdict: Verdict, remember: boolean, scope: RuleScope) => void;
}) {
  const [scope, setScope] = useState<RuleScope>('app_to_destination');
  const c = prompt.connection;

  return (
    <div className="prompt-card">
      <div className="prompt-title">New Connection Detected</div>
      <div className="prompt-details">
        <div><strong>App:</strong> {appName(c.process)}</div>
        <div><strong>Dest:</strong> {c.dst_ip}:{c.dst_port}</div>
        <div><strong>Protocol:</strong> {typeof c.protocol === 'string' ? c.protocol.toUpperCase() : 'OTHER'}</div>
        <div><strong>PID:</strong> {c.process?.pid || 'unknown'}</div>
      </div>
      <div className="prompt-scope">
        <select value={scope} onChange={e => setScope(e.target.value as RuleScope)}>
          <option value="app_to_destination">This app to this destination</option>
          <option value="app_anywhere">This app to anywhere</option>
          <option value="app_to_port">This app to this port</option>
          <option value="this_connection_only">This connection only</option>
        </select>
      </div>
      <div className="prompt-actions" style={{ marginTop: 8 }}>
        <button className="btn btn-sm btn-success" onClick={() => onRespond(prompt.id, 'allow', true, scope)}>Allow &amp; Remember</button>
        <button className="btn btn-sm btn-deny" onClick={() => onRespond(prompt.id, 'deny', true, scope)}>Deny &amp; Remember</button>
        <button className="btn btn-sm" onClick={() => onRespond(prompt.id, 'allow', false, scope)}>Allow Once</button>
        <button className="btn btn-sm" onClick={() => onRespond(prompt.id, 'deny', false, scope)}>Deny Once</button>
      </div>
    </div>
  );
}
