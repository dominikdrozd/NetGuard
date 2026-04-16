import { useState } from 'react';
import { useAuthStore } from '../stores/authStore';

export function LoginPage() {
  const [token, setToken] = useState('');
  const [error, setError] = useState(false);
  const login = useAuthStore(s => s.login);

  const handleLogin = async () => {
    if (!token.trim()) return;
    setError(false);
    const ok = await login(token.trim());
    if (!ok) setError(true);
  };

  return (
    <div className="app">
      <div className="main" style={{ marginLeft: 0, display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <div style={{ maxWidth: 400, textAlign: 'center' }}>
          <h1 style={{ color: 'var(--accent)', marginBottom: 8 }}>NetGuard</h1>
          <p style={{ color: 'var(--text-muted)', marginBottom: 24 }}>Enter API token to authenticate</p>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, marginBottom: 16 }}>
            Token is in: <code>/etc/netguard/api_token</code>
          </p>
          <input
            type="password"
            value={token}
            onChange={e => setToken(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') handleLogin(); }}
            placeholder="Paste API token..."
            autoFocus
            style={{ width: '100%', padding: '10px 14px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-primary)', fontSize: 14, marginBottom: 12 }}
          />
          {error && <div style={{ color: 'var(--red)', fontSize: 13, marginBottom: 12 }}>Invalid token</div>}
          <button className="btn btn-primary" onClick={handleLogin} style={{ width: '100%', padding: 10 }}>
            Authenticate
          </button>
        </div>
      </div>
    </div>
  );
}
