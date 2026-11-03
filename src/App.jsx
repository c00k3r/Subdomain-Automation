import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { ScannerHero } from './components/ScannerHero';
import { ScanProgress } from './components/ScanProgress';
import { ResultsView } from './components/ResultsView';
import { HistoryView } from './components/HistoryView';

export default function App() {
  const [currentView, setCurrentView] = useState('home'); // 'home' | 'scanning' | 'results' | 'history'
  const [isScanning, setIsScanning] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);

  const [activeScan, setActiveScan] = useState(null);
  const [scansList, setScansList] = useState([]);
  const [sessionToken, setSessionToken] = useState('');

  const eventSourceRef = useRef(null);
  const pollTimerRef = useRef(null);

  // Fetch cryptographic session token
  const fetchSessionToken = async () => {
    try {
      const res = await fetch('/api/session');
      if (res.ok) {
        const data = await res.json();
        if (data.token) {
          setSessionToken(data.token);
          return data.token;
        }
      }
    } catch {
      // ignore
    }
    return '';
  };

  // Fetch scan history
  const fetchHistory = async (token = sessionToken) => {
    try {
      const res = await fetch('/api/recon/history', {
        headers: token ? { 'x-reconforge-session': token } : {},
      });
      if (res.ok) {
        const data = await res.json();
        setScansList(data);
      }
    } catch {
      // ignore
    }
  };

  const fetchScanDetails = async (scanId, andShowResults = true, token = sessionToken) => {
    try {
      const res = await fetch(`/api/recon/scan/${scanId}`, {
        headers: token ? { 'x-reconforge-session': token } : {},
      });
      if (res.ok) {
        const data = await res.json();
        setActiveScan(data);
        if (data.status === 'running') {
          setIsScanning(true);
          setCurrentView('scanning');
          listenToScan(scanId, token);
        } else if (andShowResults) {
          setIsScanning(false);
          setCurrentView('results');
        }
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchSessionToken().then((token) => {
      fetchHistory(token);
    });
    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, []);

  const listenToScan = (scanId, token = sessionToken) => {
    setIsScanning(true);
    setCurrentView('scanning');

    // Clean up any previous listeners/timers
    if (eventSourceRef.current) eventSourceRef.current.close();
    if (pollTimerRef.current) clearInterval(pollTimerRef.current);

    const onFinish = (completedScan) => {
      setActiveScan(completedScan);
      setIsScanning(false);
      setCurrentView('results');
      if (eventSourceRef.current) eventSourceRef.current.close();
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      fetchHistory(token);
    };

    // 1. Server-Sent Events stream with token query parameter
    try {
      const streamToken = token || sessionToken;
      const streamUrl = `/api/recon/stream/${scanId}${streamToken ? `?token=${encodeURIComponent(streamToken)}` : ''}`;
      const es = new EventSource(streamUrl);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const update = JSON.parse(event.data);
          if (update.type === 'log') {
            setActiveScan((prev) => {
              if (!prev) return prev;
              return {
                ...prev,
                logs: [...(prev.logs || []), update.line],
              };
            });
          } else {
            setActiveScan(update);
            if (update.status === 'completed' || update.status === 'failed') {
              onFinish(update);
            }
          }
        } catch (err) {
          console.error('SSE parse error:', err);
        }
      };

      es.onerror = async () => {
        es.close();
        // Check current status on server directly
        try {
          const res = await fetch(`/api/recon/scan/${scanId}`, {
            headers: streamToken ? { 'x-reconforge-session': streamToken } : {},
          });
          if (res.ok) {
            const data = await res.json();
            setActiveScan(data);
            if (data.status === 'completed' || data.status === 'failed') {
              onFinish(data);
            }
          }
        } catch {
          // Poller below will catch it
        }
      };
    } catch {
      // Fallback to poller
    }

    // 2. Fallback Interval Poller (every 1s) to ensure we NEVER get stuck on Step 6
    pollTimerRef.current = setInterval(async () => {
      try {
        const streamToken = token || sessionToken;
        const res = await fetch(`/api/recon/scan/${scanId}`, {
          headers: streamToken ? { 'x-reconforge-session': streamToken } : {},
        });
        if (res.ok) {
          const data = await res.json();
          setActiveScan(data);
          if (data.status === 'completed' || data.status === 'failed') {
            onFinish(data);
          }
        }
      } catch {
        // ignore
      }
    }, 1000);
  };

  const handleStartScan = async (domain, allowActiveProbing = false) => {
    setErrorMessage(null);
    setIsScanning(true);
    setCurrentView('scanning');

    try {
      let token = sessionToken;
      if (!token) {
        token = await fetchSessionToken();
      }

      const res = await fetch('/api/recon/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-reconforge-session': token || '',
        },
        body: JSON.stringify({ domain, allowActiveProbing }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to start reconnaissance scan');
      }

      const { scanId } = await res.json();
      fetchScanDetails(scanId, false, token);
      listenToScan(scanId, token);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to start scan');
      setIsScanning(false);
      setCurrentView('home');
    }
  };

  const handleNewScan = () => {
    setErrorMessage(null);
    setCurrentView('home');
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0e1017] text-slate-100 font-sans selection:bg-indigo-500/30 selection:text-indigo-200">
      <Navbar
        currentView={currentView}
        onViewChange={(view) => setCurrentView(view)}
        onNewScan={handleNewScan}
        hasActiveScan={!!activeScan}
      />

      <main className="flex-1 flex flex-col">
        {currentView === 'home' && (
          <ScannerHero
            onStartScan={handleStartScan}
            isScanning={isScanning}
            errorMessage={errorMessage}
          />
        )}

        {currentView === 'scanning' && (
          <ScanProgress
            scan={activeScan}
            onComplete={() => {
              setIsScanning(false);
              setCurrentView('results');
            }}
          />
        )}

        {currentView === 'results' && (
          <ResultsView
            scan={activeScan}
            onNewScan={handleNewScan}
          />
        )}

        {currentView === 'history' && (
          <HistoryView
            scans={scansList}
            onSelectScan={(id) => fetchScanDetails(id, true)}
            onBack={() => setCurrentView(activeScan ? 'results' : 'home')}
          />
        )}
      </main>
    </div>
  );
}
