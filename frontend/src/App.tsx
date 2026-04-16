import { useEffect, useState } from 'react';
import { HashRouter, Routes, Route } from 'react-router-dom';
import { useAuthStore } from './stores/authStore';
import { usePromptStore } from './stores/promptStore';
import { useWebSocket } from './hooks/useWebSocket';
import { api } from './hooks/useApi';
import { Sidebar } from './components/layout/Sidebar';
import { DashboardPage } from './components/dashboard/DashboardPage';
import { ConnectionsPage } from './components/connections/ConnectionsPage';
import { RulesPage } from './components/rules/RulesPage';
import { LogsPage } from './components/logs/LogsPage';
import { PromptOverlay } from './components/prompts/PromptOverlay';
import { PacketDetailModal } from './components/modals/PacketDetailModal';
import { LoginPage } from './pages/LoginPage';
import type { PendingPrompt } from './types';

export default function App() {
  const token = useAuthStore(s => s.token);
  const validateExisting = useAuthStore(s => s.validateExisting);
  const [loading, setLoading] = useState(true);
  const [selectedConnection, setSelectedConnection] = useState<string | null>(null);

  useEffect(() => {
    validateExisting().finally(() => setLoading(false));
  }, [validateExisting]);

  if (loading) return null;
  if (!token) return <LoginPage />;

  return <AuthenticatedApp selectedConnection={selectedConnection} setSelectedConnection={setSelectedConnection} />;
}

function AuthenticatedApp({ selectedConnection, setSelectedConnection }: {
  selectedConnection: string | null;
  setSelectedConnection: (id: string | null) => void;
}) {
  const setPrompts = usePromptStore(s => s.setPrompts);
  useWebSocket();

  useEffect(() => {
    api<PendingPrompt[]>('/prompts').then(setPrompts).catch(() => {});
  }, [setPrompts]);

  return (
    <HashRouter>
      <div className="app">
        <Sidebar />
        <main className="main">
          <Routes>
            <Route path="/" element={<DashboardPage onSelectConnection={setSelectedConnection} />} />
            <Route path="/connections" element={<ConnectionsPage onSelect={setSelectedConnection} />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/logs" element={<LogsPage onSelect={setSelectedConnection} />} />
          </Routes>
        </main>
        <PromptOverlay />
        <PacketDetailModal connectionId={selectedConnection} onClose={() => setSelectedConnection(null)} />
      </div>
    </HashRouter>
  );
}
