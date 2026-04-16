import { useEffect, useState } from 'react';
import { api } from '../../hooks/useApi';
import { useRuleStore } from '../../stores/ruleStore';
import { VerdictBadge, ProtocolBadge } from '../common/Badge';
import { ModalBackdrop } from '../common/ModalBackdrop';
import type { Rule, CreateRuleRequest, Verdict, Direction, Protocol } from '../../types';

export function RulesPage() {
  const rules = useRuleStore(s => s.rules);
  const setRules = useRuleStore(s => s.setRules);
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    api<Rule[]>('/rules').then(setRules).catch(() => {});
  }, [setRules]);

  const toggleRule = async (id: string) => {
    try { await api(`/rules/${id}/toggle`, { method: 'PATCH' }); api<Rule[]>('/rules').then(setRules); } catch {}
  };

  const deleteRule = async (id: string) => {
    if (!confirm('Delete this rule?')) return;
    try { await api(`/rules/${id}`, { method: 'DELETE' }); setRules(rules.filter(r => r.id !== id)); } catch {}
  };

  return (
    <>
      <div className="card">
        <div className="card-header">
          <h2>Firewall Rules</h2>
          <button className="btn btn-primary" onClick={() => setShowModal(true)}>+ Add Rule</button>
        </div>
        <div className="card-body-full">
          <table>
            <thead>
              <tr><th>Enabled</th><th>Application</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Direction</th><th>Verdict</th><th>Hits</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {rules.length === 0 ? (
                <tr><td colSpan={9} className="empty-state">No rules defined. Click "+ Add Rule" to create one.</td></tr>
              ) : rules.map(r => (
                <tr key={r.id}>
                  <td>
                    <label className="toggle">
                      <input type="checkbox" checked={r.enabled} onChange={() => toggleRule(r.id)} />
                      <span className="slider" />
                    </label>
                  </td>
                  <td className="text-mono truncate">{r.app_path}</td>
                  <td className="text-mono">{r.remote_host || '*'}</td>
                  <td>{r.remote_port || '*'}</td>
                  <td>{r.protocol ? <ProtocolBadge protocol={r.protocol} /> : 'Any'}</td>
                  <td>{r.direction || 'Both'}</td>
                  <td><VerdictBadge verdict={r.verdict} /></td>
                  <td>{r.hit_count}</td>
                  <td><button className="btn btn-sm btn-danger" onClick={() => deleteRule(r.id)}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <RuleFormModal open={showModal} onClose={() => setShowModal(false)} onCreated={() => { setShowModal(false); api<Rule[]>('/rules').then(setRules); }} />
    </>
  );
}

function RuleFormModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [appPath, setAppPath] = useState('');
  const [remoteHost, setRemoteHost] = useState('');
  const [remotePort, setRemotePort] = useState('');
  const [protocol, setProtocol] = useState('');
  const [direction, setDirection] = useState('');
  const [verdict, setVerdict] = useState<Verdict>('allow');
  const [note, setNote] = useState('');

  const save = async () => {
    const req: CreateRuleRequest = {
      app_path: appPath || '*',
      remote_host: remoteHost || null,
      remote_port: remotePort ? parseInt(remotePort) : null,
      protocol: (protocol || null) as Protocol | null,
      direction: (direction || null) as Direction | null,
      verdict,
      temporary: false,
      note: note || null,
    };
    try {
      await api('/rules', { method: 'POST', body: JSON.stringify(req) });
      setAppPath(''); setRemoteHost(''); setRemotePort(''); setProtocol(''); setDirection(''); setVerdict('allow'); setNote('');
      onCreated();
    } catch (e: any) { alert('Failed: ' + e.message); }
  };

  return (
    <ModalBackdrop open={open} onClose={onClose}>
      <h2>Add Rule</h2>
      <div className="form-group"><label>Application Path</label><input value={appPath} onChange={e => setAppPath(e.target.value)} placeholder="/usr/bin/curl" /></div>
      <div className="form-group"><label>Remote Host</label><input value={remoteHost} onChange={e => setRemoteHost(e.target.value)} placeholder="*.example.com" /></div>
      <div className="form-group"><label>Remote Port</label><input type="number" value={remotePort} onChange={e => setRemotePort(e.target.value)} placeholder="443" /></div>
      <div className="form-group"><label>Protocol</label>
        <select value={protocol} onChange={e => setProtocol(e.target.value)}><option value="">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option></select>
      </div>
      <div className="form-group"><label>Direction</label>
        <select value={direction} onChange={e => setDirection(e.target.value)}><option value="">Both</option><option value="outbound">Outbound</option><option value="inbound">Inbound</option></select>
      </div>
      <div className="form-group"><label>Verdict</label>
        <select value={verdict} onChange={e => setVerdict(e.target.value as Verdict)}><option value="allow">Allow</option><option value="deny">Deny</option></select>
      </div>
      <div className="form-group"><label>Note</label><input value={note} onChange={e => setNote(e.target.value)} placeholder="Description..." /></div>
      <div className="form-actions">
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={save}>Save Rule</button>
      </div>
    </ModalBackdrop>
  );
}
