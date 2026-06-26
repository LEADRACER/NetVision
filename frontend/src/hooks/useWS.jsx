import { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react';

const WSContext = createContext(null);

export function WSProvider({ children }) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState([]);
  const [lastState, setLastState] = useState(null);
  const wsRef = useRef(null);
  const maxEvents = 200;

  const connect = useCallback(() => {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${location.host}/ws`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      // Subscribe to all event streams
      ws.send(JSON.stringify({
        type: 'subscribe',
        topics: ['scan.progress', 'scan.complete', 'health.alert', 'vuln.found',
                 'capture.data', 'capture.alert', 'system.status', 'device.update'],
      }));
    };

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        if (data.type === 'state') {
          setLastState(data);
          return;
        }
        if (data.type === 'subscribed') return;
        if (data.type === 'pong') return;

        const event = { ...data, _received: Date.now() };
        setEvents(prev => {
          const next = [event, ...prev];
          return next.length > maxEvents ? next.slice(0, maxEvents) : next;
        });
      } catch { /* ignore parse errors */ }
    };

    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;
      setTimeout(connect, 3000);
    };

    ws.onerror = () => ws.close();
  }, []);

  const send = useCallback((msg) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  useEffect(() => {
    connect();
    return () => { wsRef.current?.close(); };
  }, [connect]);

  return (
    <WSContext.Provider value={{ connected, events, lastState, send }}>
      {children}
    </WSContext.Provider>
  );
}

export function useWS() {
  const ctx = useContext(WSContext);
  if (!ctx) throw new Error('useWS must be inside WSProvider');
  return ctx;
}
