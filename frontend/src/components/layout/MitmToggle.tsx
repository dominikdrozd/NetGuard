import { useEffect, useState } from 'react';
import { api } from '../../hooks/useApi';
import { useAuthStore } from '../../stores/authStore';

interface MitmStatus {
  enabled: boolean;
  listen_addr: string;
  listen_port: number;
  ca_cert_path: string;
  ca_cert_installed: boolean;
  allow_runtime_toggle: boolean;
}

export function MitmToggle() {
  const [status, setStatus] = useState<MitmStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const token = useAuthStore(s => s.token);

  const refresh = () => {
    api<MitmStatus>('/mitmproxy')
      .then(setStatus)
      .catch(e => setError(e.message));
  };

  useEffect(refresh, []);

  const toggle = async () => {
    if (!status || busy) return;
    setBusy(true);
    setError(null);
    try {
      const endpoint = status.enabled ? '/mitmproxy/disable' : '/mitmproxy/enable';
      const next = await api<MitmStatus>(endpoint, { method: 'POST' });
      setStatus(next);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  // Fetch CA through the authenticated API (Bearer in header), then save via a blob URL.
  // This avoids needing to expose the cert via a public URL or embed the auth token in a link.
  const downloadCert = async () => {
    setError(null);
    try {
      const res = await fetch('/api/mitmproxy/ca-cert', {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'netguard-mitm-ca.pem';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setError(e.message);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
  };

  if (!status) return null;

  return (
    <div style={{
      padding: '10px 14px',
      borderTop: '1px solid var(--border)',
      fontSize: 12,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontWeight: 600 }}>HTTPS Decrypt</span>
        {status.allow_runtime_toggle ? (
          <button
            className="btn btn-sm"
            onClick={toggle}
            disabled={busy}
            style={{
              background: status.enabled ? 'var(--green)' : 'var(--bg-elev)',
              color: status.enabled ? '#fff' : 'var(--text-muted)',
              minWidth: 60,
            }}
            title="Toggle HTTPS decryption on/off at runtime"
          >
            {busy ? '...' : status.enabled ? 'ON' : 'OFF'}
          </button>
        ) : (
          <span
            style={{
              padding: '2px 8px',
              borderRadius: 4,
              background: status.enabled ? 'var(--green)' : 'var(--bg-elev)',
              color: status.enabled ? '#fff' : 'var(--text-muted)',
              fontSize: 11,
            }}
            title="Runtime toggle disabled; set [mitmproxy].allow_runtime_toggle=true in netguard.toml"
          >
            {status.enabled ? 'ON' : 'OFF'}
          </span>
        )}
      </div>
      {!status.allow_runtime_toggle && (
        <div style={{ color: 'var(--text-muted)', fontSize: 11, marginBottom: 4 }}>
          Runtime toggle disabled. Edit <code>netguard.toml</code> to enable.
        </div>
      )}
      {status.enabled && (
        <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
          Listening on {status.listen_addr}:{status.listen_port}
        </div>
      )}

      {status.ca_cert_installed ? (
        <div style={{ marginTop: 6, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <button className="btn btn-sm" onClick={downloadCert}>Download CA</button>
          <button
            className="btn btn-sm"
            onClick={() => setShowHelp(v => !v)}
            style={{ background: 'var(--bg-elev)' }}
          >
            {showHelp ? 'Hide help' : 'How to install'}
          </button>
        </div>
      ) : (
        <div style={{ marginTop: 6, color: 'var(--text-muted)', fontSize: 11 }}>
          CA not yet generated. Run <code>deploy.sh</code> first.
        </div>
      )}

      {showHelp && (
        <div style={{ marginTop: 8, padding: 8, background: 'var(--bg-elev)', borderRadius: 4, fontSize: 11, lineHeight: 1.5 }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>System trust (cURL, Go, Python, etc.)</div>
          <div className="text-mono" style={{ color: 'var(--text-muted)' }}>
            sudo cp ~/Downloads/netguard-mitm-ca.pem /usr/local/share/ca-certificates/netguard-mitm.crt && sudo update-ca-certificates
          </div>
          <button
            className="btn btn-sm"
            style={{ marginTop: 4, marginBottom: 8 }}
            onClick={() => copyToClipboard('sudo cp ~/Downloads/netguard-mitm-ca.pem /usr/local/share/ca-certificates/netguard-mitm.crt && sudo update-ca-certificates')}
          >
            Copy command
          </button>

          <div style={{ fontWeight: 600, marginTop: 4, marginBottom: 4 }}>Firefox</div>
          <div style={{ color: 'var(--text-muted)' }}>
            Preferences &rarr; Privacy &amp; Security &rarr; Certificates &rarr; View Certificates &rarr; Authorities &rarr; Import
          </div>
          <button
            className="btn btn-sm"
            style={{ marginTop: 4, marginBottom: 8 }}
            onClick={() => copyToClipboard('about:preferences#privacy')}
          >
            Copy about:preferences URL
          </button>

          <div style={{ fontWeight: 600, marginTop: 4, marginBottom: 4 }}>Chromium / Chrome</div>
          <div style={{ color: 'var(--text-muted)' }}>
            Paste in a new tab: <code>chrome://settings/certificates</code> &rarr; Authorities &rarr; Import
          </div>
          <button
            className="btn btn-sm"
            style={{ marginTop: 4 }}
            onClick={() => copyToClipboard('chrome://settings/certificates')}
          >
            Copy chrome:// URL
          </button>

          <div style={{ marginTop: 8, color: 'var(--text-muted)', fontStyle: 'italic' }}>
            Browsers forbid scripted cert install for security reasons — you'll need to click Import + Trust manually after opening the pages above.
          </div>
        </div>
      )}

      {error && (
        <div style={{ color: 'var(--red)', fontSize: 11, marginTop: 4 }}>
          {error}
        </div>
      )}
    </div>
  );
}
