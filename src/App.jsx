import React, { useState, useEffect } from 'react';
import {
  Search,
  Play,
  Terminal,
  Globe,
  Activity,
  FileText,
  Clock,
  AlertCircle,
  RotateCcw,
  Maximize2,
  Minimize2,
  Shield,
  Layers,
  ArrowRight
} from 'lucide-react';
import { Navbar } from './components/Navbar';
import { TerminalLog } from './components/TerminalLog';
import { ScanWorkflow } from './components/ScanWorkflow';
import { SubdomainsTable } from './components/SubdomainsTable';
import { LiveHostsTable } from './components/LiveHostsTable';
import { ReportsViewer } from './components/ReportsViewer';
import { HistorySidebar } from './components/HistorySidebar';

export default function App() {
  const [domainInput, setDomainInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);

  const [activeScan, setActiveScan] = useState(null);
  const [scansList, setScansList] = useState([]);
  const [activeTab, setActiveTab] = useState('live'); // 'live' | 'subdomains' | 'reports'
  const [layoutMode, setLayoutMode] = useState('split'); // 'split' | 'data-only' | 'terminal-only'

  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/recon/history');
      if (res.ok) {
        const data = await res.json();
        setScansList(data);
        if (data.length > 0 && !activeScan) {
          fetchScanDetails(data[0].id);
        }
      }
    } catch {
      // ignore
    }
  };

  const fetchScanDetails = async (scanId) => {
    try {
      const res = await fetch(`/api/recon/scan/${scanId}`);
      if (res.ok) {
        const data = await res.json();
        setActiveScan(data);
        if (data.status === 'running') {
          listenToScanSSE(scanId);
        }
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const listenToScanSSE = (scanId) => {
    setIsScanning(true);
    const eventSource = new EventSource(`/api/recon/stream/${scanId}`);

    eventSource.onmessage = (event) => {
      try {
        const update = JSON.parse(event.data);
        setActiveScan(update);
        if (update.status === 'completed' || update.status === 'failed') {
          setIsScanning(false);
          eventSource.close();
          fetchHistory();
        }
      } catch (err) {
        console.error('SSE parse error:', err);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      setIsScanning(false);
      fetchHistory();
    };
  };

  const startScan = async (targetDomain) => {
    const domain = (targetDomain || domainInput).trim();
    if (!domain) {
      setErrorMessage('Enter an authorized target domain (e.g. hackerone.com)');
      return;
    }

    setErrorMessage(null);
    setIsScanning(true);

    try {
      const res = await fetch('/api/recon/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to start reconnaissance pipeline');
      }

      const { scanId } = await res.json();
      fetchScanDetails(scanId);
      listenToScanSSE(scanId);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to start reconnaissance pipeline');
      setIsScanning(false);
    }
  };

  const quickPresets = ['hackerone.com', 'owasp.org', 'mozilla.org', 'github.com'];

  // Calculate status breakdown for the HUD mini-bar
  const statusStats = React.useMemo(() => {
    if (!activeScan?.aliveHosts?.length) return null;
    const hosts = activeScan.aliveHosts;
    const c2xx = hosts.filter(h => h.statusCode >= 200 && h.statusCode < 300).length;
    const c3xx = hosts.filter(h => h.statusCode >= 300 && h.statusCode < 400).length;
    const c4xx = hosts.filter(h => h.statusCode >= 400 && h.statusCode < 500).length;
    const c5xx = hosts.filter(h => h.statusCode >= 500).length;
    const cdns = hosts.filter(h => h.statusCode === 0).length;
    return {
      total: hosts.length,
      c2xx, c3xx, c4xx, c5xx, cdns,
      p2xx: (c2xx / hosts.length) * 100,
      p3xx: (c3xx / hosts.length) * 100,
      p4xx: (c4xx / hosts.length) * 100,
      p5xx: (c5xx / hosts.length) * 100,
      pdns: (cdns / hosts.length) * 100,
    };
  }, [activeScan]);

  return (
    <div className="min-h-screen flex flex-col bg-[#07080c] text-slate-200 tactical-grid antialiased selection:bg-emerald-500/25 selection:text-emerald-300">
      <Navbar isScanning={isScanning} activeScan={activeScan} />

      <main className="flex-1 max-w-[1520px] w-full mx-auto p-3 sm:p-5 lg:p-6 space-y-4">
        {/* Scoping Command Deck */}
        <section className="bg-[#0b0e15] border border-[#1a1f2c] rounded-xl p-3.5 sm:p-4 shadow-xl">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex items-center space-x-2">
              <span className="font-mono text-xs text-emerald-400 font-bold">root@scoper:</span>
              <span className="text-xs font-mono text-slate-400">Target Scoping Console</span>
            </div>

            <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-400">
              <span className="text-slate-500">QUICK SCOPES:</span>
              <div className="flex flex-wrap gap-1">
                {quickPresets.map((preset) => (
                  <button
                    key={preset}
                    onClick={() => {
                      setDomainInput(preset);
                      startScan(preset);
                    }}
                    disabled={isScanning}
                    className="px-2 py-0.5 rounded bg-[#10141e] hover:bg-[#181d2a] text-slate-300 hover:text-emerald-400 border border-slate-800 transition-colors disabled:opacity-40"
                  >
                    {preset}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              startScan();
            }}
            className="mt-3 flex flex-col sm:flex-row gap-2"
          >
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 font-mono text-xs">
                target://
              </div>
              <input
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="domain.tld (e.g. hackerone.com, owasp.org)"
                disabled={isScanning}
                className="w-full pl-20 pr-4 py-2 text-xs sm:text-sm bg-[#06080d] border border-slate-800 rounded-lg text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500 font-mono transition-colors disabled:opacity-50"
              />
            </div>

            <button
              type="submit"
              disabled={isScanning}
              className="inline-flex items-center justify-center px-5 py-2 rounded-lg text-xs sm:text-sm font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 focus:outline-none focus:ring-1 focus:ring-emerald-400 transition-all disabled:opacity-50 font-mono tracking-wide shadow-[0_0_15px_rgba(16,185,129,0.2)] shrink-0"
            >
              {isScanning ? (
                <>
                  <RotateCcw className="w-4 h-4 mr-1.5 animate-spin" />
                  <span>ENGAGED...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 mr-1.5 fill-current" />
                  <span>ENGAGE PIPELINE</span>
                </>
              )}
            </button>
          </form>

          {errorMessage && (
            <div className="mt-2 text-xs font-mono text-rose-400 bg-rose-950/30 border border-rose-900/50 px-3 py-1.5 rounded flex items-center space-x-2">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}
        </section>

        {/* Tactical Pipeline Progression */}
        <ScanWorkflow
          step={activeScan?.step || 0}
          isScanning={isScanning}
          totalSubdomains={activeScan?.totalSubdomains || 0}
          aliveCount={activeScan?.aliveCount || 0}
        />

        {/* Unified Mission Telemetry Ribbon (Anti-Card AI Slop) */}
        {activeScan && (
          <div className="bg-[#0b0e15] border border-[#1a1f2c] rounded-xl p-3 flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono text-xs">
            <div className="flex items-center space-x-4 flex-wrap gap-y-2">
              <div>
                <span className="text-slate-500 uppercase text-[10px]">Target Apex</span>
                <div className="text-sm font-bold text-slate-100 tracking-tight">
                  {activeScan.domain}
                </div>
              </div>

              <div className="h-6 w-px bg-slate-800 hidden sm:block" />

              <div>
                <span className="text-slate-500 uppercase text-[10px]">Discovered Assets</span>
                <div className="text-sm font-bold text-cyan-400 tabular-nums">
                  {activeScan.totalSubdomains}
                </div>
              </div>

              <div className="h-6 w-px bg-slate-800 hidden sm:block" />

              <div>
                <span className="text-slate-500 uppercase text-[10px]">Live Reachable</span>
                <div className="text-sm font-bold text-emerald-400 tabular-nums flex items-center space-x-1">
                  <span>{activeScan.aliveCount}</span>
                  {activeScan.totalSubdomains > 0 && (
                    <span className="text-[11px] text-slate-400 font-normal">
                      ({Math.round((activeScan.aliveCount / activeScan.totalSubdomains) * 100)}%)
                    </span>
                  )}
                </div>
              </div>

              <div className="h-6 w-px bg-slate-800 hidden sm:block" />

              <div>
                <span className="text-slate-500 uppercase text-[10px]">Elapsed Time</span>
                <div className="text-sm font-bold text-amber-400 tabular-nums">
                  {activeScan.executionTime ? `${activeScan.executionTime}s` : isScanning ? 'running...' : '0s'}
                </div>
              </div>
            </div>

            {/* Response Code Spectrum Bar */}
            {statusStats && statusStats.total > 0 && (
              <div className="space-y-1 min-w-[200px]">
                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span>HTTP SPECTRUM</span>
                  <span className="text-slate-500">{statusStats.total} responses</span>
                </div>
                <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden flex">
                  {statusStats.p2xx > 0 && (
                    <div style={{ width: `${statusStats.p2xx}%` }} className="bg-emerald-500 h-full" title={`2xx Success: ${statusStats.c2xx}`} />
                  )}
                  {statusStats.p3xx > 0 && (
                    <div style={{ width: `${statusStats.p3xx}%` }} className="bg-sky-400 h-full" title={`3xx Redirect: ${statusStats.c3xx}`} />
                  )}
                  {statusStats.p4xx > 0 && (
                    <div style={{ width: `${statusStats.p4xx}%` }} className="bg-amber-400 h-full" title={`4xx Client: ${statusStats.c4xx}`} />
                  )}
                  {statusStats.p5xx > 0 && (
                    <div style={{ width: `${statusStats.p5xx}%` }} className="bg-rose-500 h-full" title={`5xx Error: ${statusStats.c5xx}`} />
                  )}
                  {statusStats.pdns > 0 && (
                    <div style={{ width: `${statusStats.pdns}%` }} className="bg-slate-700 h-full" title={`DNS Only: ${statusStats.cdns}`} />
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Main Workstation Workspace: Split vs Focused */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Main Left Pane (Data Explorer) */}
          <div className={`${
            layoutMode === 'data-only'
              ? 'lg:col-span-12'
              : layoutMode === 'terminal-only'
              ? 'hidden'
              : 'lg:col-span-7 xl:col-span-8'
          } space-y-3`}>
            {/* View Selector Tabs & Layout Controls */}
            <div className="flex items-center justify-between border-b border-[#181c26] pb-2 font-mono text-xs">
              <div className="flex items-center space-x-1 sm:space-x-2">
                <button
                  onClick={() => setActiveTab('live')}
                  className={`px-3 py-1.5 rounded-lg flex items-center space-x-2 transition-colors ${
                    activeTab === 'live'
                      ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Activity className="w-3.5 h-3.5" />
                  <span>Live Hosts ({activeScan?.aliveHosts?.length || 0})</span>
                </button>

                <button
                  onClick={() => setActiveTab('subdomains')}
                  className={`px-3 py-1.5 rounded-lg flex items-center space-x-2 transition-colors ${
                    activeTab === 'subdomains'
                      ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Attack Surface ({activeScan?.subdomains?.length || 0})</span>
                </button>

                <button
                  onClick={() => setActiveTab('reports')}
                  className={`px-3 py-1.5 rounded-lg flex items-center space-x-2 transition-colors ${
                    activeTab === 'reports'
                      ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Report Artifacts</span>
                </button>
              </div>

              {/* Layout Mode Switcher */}
              <div className="hidden sm:flex items-center space-x-1 text-slate-500">
                <button
                  onClick={() => setLayoutMode(layoutMode === 'data-only' ? 'split' : 'data-only')}
                  className="p-1.5 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
                  title={layoutMode === 'data-only' ? 'Restore Split View' : 'Maximize Data Explorer'}
                >
                  {layoutMode === 'data-only' ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {/* Active Content Component */}
            <div>
              {activeTab === 'live' && (
                <LiveHostsTable
                  aliveHosts={activeScan?.aliveHosts || []}
                  scanId={activeScan?.id || ''}
                />
              )}

              {activeTab === 'subdomains' && (
                <SubdomainsTable
                  subdomains={activeScan?.subdomains || []}
                  domain={activeScan?.domain || ''}
                  scanId={activeScan?.id || ''}
                />
              )}

              {activeTab === 'reports' && (
                <ReportsViewer scan={activeScan} />
              )}
            </div>
          </div>

          {/* Right Pane (Live Terminal Engine & Past Missions) */}
          <div className={`${
            layoutMode === 'terminal-only'
              ? 'lg:col-span-12'
              : layoutMode === 'data-only'
              ? 'hidden'
              : 'lg:col-span-5 xl:col-span-4'
          } space-y-4`}>
            {/* Terminal Viewport */}
            <TerminalLog
              logs={activeScan?.logs || []}
              isScanning={isScanning}
            />

            {/* Past Scans Drawer */}
            <div className="h-[260px]">
              <HistorySidebar
                scans={scansList}
                currentScanId={activeScan?.id || ''}
                onSelectScan={(id) => fetchScanDetails(id)}
              />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
