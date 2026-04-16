import { useEffect, useRef } from 'react';
import { useAuthStore } from '../stores/authStore';
import { useConnectionStore } from '../stores/connectionStore';
import { useRuleStore } from '../stores/ruleStore';
import { usePromptStore } from '../stores/promptStore';
import { useStatsStore } from '../stores/statsStore';
import { useWsStore } from '../stores/websocketStore';
import type { WsEvent } from '../types';

export function useWebSocket() {
  const token = useAuthStore(s => s.token);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    if (!token) return;

    let cancelled = false;

    async function connect() {
      if (cancelled) return;
      useWsStore.getState().setStatus('connecting');

      try {
        const res = await fetch('/ws-ticket', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (!res.ok || cancelled) {
          scheduleReconnect();
          return;
        }
        const ticket = await res.text();
        if (cancelled) return;

        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${proto}//${location.host}/ws?ticket=${encodeURIComponent(ticket)}`);
        wsRef.current = ws;

        ws.onopen = () => {
          if (!cancelled) useWsStore.getState().setStatus('connected');
        };

        ws.onclose = () => {
          if (!cancelled) {
            useWsStore.getState().setStatus('disconnected');
            scheduleReconnect();
          }
        };

        ws.onerror = () => ws.close();

        ws.onmessage = (evt) => {
          try {
            const msg: WsEvent = JSON.parse(evt.data);
            handleEvent(msg);
          } catch {}
        };
      } catch {
        if (!cancelled) scheduleReconnect();
      }
    }

    function scheduleReconnect() {
      reconnectTimer.current = setTimeout(connect, 3000);
    }

    connect();

    return () => {
      cancelled = true;
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [token]);

  return wsRef;
}

function handleEvent(msg: WsEvent) {
  switch (msg.type) {
    case 'new_connection':
      useConnectionStore.getState().addConnection(msg.data);
      break;
    case 'connection_enriched':
      useConnectionStore.getState().enrichConnection(msg.data.id, msg.data.fields);
      break;
    case 'prompt':
      usePromptStore.getState().addPrompt(msg.data);
      break;
    case 'prompt_resolved':
      usePromptStore.getState().removePrompt(msg.data.prompt_id);
      break;
    case 'rule_changed':
      useRuleStore.getState().updateRule(msg.data);
      break;
    case 'stats':
      useStatsStore.getState().setStats(msg.data);
      break;
  }
}
