import { NavLink } from 'react-router-dom';
import { useWsStore } from '../../stores/websocketStore';

export function Sidebar() {
  const status = useWsStore(s => s.status);

  return (
    <nav className="sidebar">
      <div className="sidebar-logo">
        <h1>NetGuard</h1>
        <div className="subtitle">Application Firewall</div>
      </div>
      <NavLink to="/" end className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
        <span className="nav-icon">&#9673;</span> Dashboard
      </NavLink>
      <NavLink to="/connections" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
        <span className="nav-icon">&#8644;</span> Connections
      </NavLink>
      <NavLink to="/rules" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
        <span className="nav-icon">&#9881;</span> Rules
      </NavLink>
      <NavLink to="/logs" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
        <span className="nav-icon">&#9776;</span> Logs
      </NavLink>
      <div style={{ flex: 1 }} />
      <div className="nav-item" style={{ cursor: 'default' }}>
        <span className={`status-dot ${status === 'connected' ? 'connected' : 'disconnected'}`} />
        <span>{status === 'connected' ? 'Connected' : status === 'connecting' ? 'Connecting...' : 'Disconnected'}</span>
      </div>
    </nav>
  );
}
