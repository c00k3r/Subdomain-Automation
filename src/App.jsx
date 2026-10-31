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
  RotateCcw
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
  const [activeTab, setActiveTab] = useState('terminal');

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
      setErrorMessage('Please enter a target domain (e.g. hackerone.com)');
      return;
    }

    setErrorMessage(null);
    setIsScanning(true);
    setActiveTab('terminal');

    try {
      const res = await fetch('/api/recon/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to start scan');
      }

      const { scanId } = await res.json();
      fetchScanDetails(scanId);
      listenToScanSSE(scanId);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to start reconnaissance scan');
      setIsScanning(false);
    }
  };

  const quickPresets = ['hackerone.com', 'owasp.org', 'mozilla.org', 'github.com'];

  return (
    <div className="min-h-screen flex flex-col bg-[#020617] text-slate-100 font-sans selection:bg-blue-500/30">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Top Control Section: Domain Input & Quick Presets */}
        <div className="p-5 sm:p-6 rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-xl shadow-xl">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-1">
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
                <span>Target Domain Reconnaissance</span>
              </h1>
              <p className="text-xs sm:text-sm text-slate-400">
                Automated passive subdomain discovery, live host probing, and report generation.
              </p>
            </div>

            <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
              <span className="hidden sm:inline">Presets:</span>
              <div className="flex flex-wrap gap-1.5">
                {quickPresets.map((preset) => (
                  <button
                    key={preset}
                    onClick={() => {
                      setDomainInput(preset);
                      startScan(preset);
                    }}
                    disabled={isScanning}
                    className="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors disabled:opacity-50 text-[11px]"
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
            className="mt-5 flex flex-col sm:flex-row gap-2.5"
          >
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <Search className="h-4 w-4 text-slate-500" />
              </div>
              <input
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="Enter domain (e.g. hackerone.com, owasp.org)"
                disabled={isScanning}
                className="block w-full pl-10 pr-4 py-2.5 text-sm bg-slate-950 border border-slate-700 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono transition-all disabled:opacity-50"
              />
            </div>

            <button
              type="submit"
              disabled={isScanning}
              className="inline-flex items-center justify-center px-6 py-2.5 rounded-xl text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-blue-600/30 font-mono"
            >
              {isScanning ? (
                <>
                  <RotateCcw className="w-4 h-4 mr-2 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 mr-2 fill-current" />
                  <span>Start Recon</span>
                </>
              )}
            </button>
          </form>

          {errorMessage && (
            <div className="mt-3 text-xs text-rose-400 bg-rose-950/40 border border-rose-800/60 px-3 py-2 rounded-lg flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}
        </div>

        {/* 6-Stage Workflow Progress */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400 px-1 font-mono">
            <span>AUTOMATION PIPELINE</span>
            {activeScan && (
              <span className="text-slate-300">
                Target: <span className="text-cyan-400 font-bold">{activeScan.domain}</span>
              </span>
            )}
          </div>
          <ScanWorkflow
            step={activeScan?.step || 0}
            isScanning={isScanning}
            totalSubdomains={activeScan?.totalSubdomains || 0}
            aliveCount={activeScan?.aliveCount || 0}
          />
        </div>

        {/* Scan Metric Statistics */}
        {activeScan && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/40">
              <div className="text-[11px] text-slate-400 font-mono">Target Domain</div>
              <div className="text-base sm:text-lg font-bold text-slate-100 truncate mt-0.5">
                {activeScan.domain}
              </div>
            </div>

            <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/40">
              <div className="text-[11px] text-slate-400 font-mono">Unique Subdomains</div>
              <div className="text-base sm:text-lg font-bold text-cyan-400 mt-0.5">
                {activeScan.totalSubdomains}
              </div>
            </div>

            <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/40">
              <div className="text-[11px] text-slate-400 font-mono">Live Hosts (Alive)</div>
              <div className="text-base sm:text-lg font-bold text-emerald-400 mt-0.5">
                {activeScan.aliveCount}
              </div>
            </div>

            <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/40">
              <div className="text-[11px] text-slate-400 font-mono">Execution Time</div>
              <div className="text-base sm:text-lg font-bold text-amber-400 mt-0.5 flex items-center space-x-1">
                <Clock className="w-4 h-4 inline" />
                <span>{activeScan.executionTime ? `${activeScan.executionTime}s` : isScanning ? 'in progress' : '0s'}</span>
              </div>
            </div>
          </div>
        )}

        {/* Main Content Area: Tabs + History Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-3 space-y-4">
            <div className="flex border-b border-slate-800 space-x-1 sm:space-x-3 text-xs sm:text-sm font-medium">
              <button
                onClick={() => setActiveTab('terminal')}
                className={`pb-2.5 px-3 flex items-center space-x-2 border-b-2 transition-colors ${
                  activeTab === 'terminal'
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Terminal className="w-4 h-4" />
                <span>Terminal Output</span>
              </button>

              <button
                onClick={() => setActiveTab('subdomains')}
                className={`pb-2.5 px-3 flex items-center space-x-2 border-b-2 transition-colors ${
                  activeTab === 'subdomains'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Globe className="w-4 h-4" />
                <span>Subdomains ({activeScan?.subdomains?.length || 0})</span>
              </button>

              <button
                onClick={() => setActiveTab('alive')}
                className={`pb-2.5 px-3 flex items-center space-x-2 border-b-2 transition-colors ${
                  activeTab === 'alive'
                    ? 'border-emerald-500 text-emerald-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Activity className="w-4 h-4" />
                <span>Live Hosts ({activeScan?.aliveHosts?.length || 0})</span>
              </button>

              <button
                onClick={() => setActiveTab('reports')}
                className={`pb-2.5 px-3 flex items-center space-x-2 border-b-2 transition-colors ${
                  activeTab === 'reports'
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileText className="w-4 h-4" />
                <span>Reports & Logs</span>
              </button>
            </div>

            <div>
              {activeTab === 'terminal' && (
                <TerminalLog
                  logs={activeScan?.logs || []}
                  isScanning={isScanning}
                />
              )}

              {activeTab === 'subdomains' && (
                <SubdomainsTable
                  subdomains={activeScan?.subdomains || []}
                  domain={activeScan?.domain || ''}
                  scanId={activeScan?.id || ''}
                />
              )}

              {activeTab === 'alive' && (
                <LiveHostsTable
                  aliveHosts={activeScan?.aliveHosts || []}
                  scanId={activeScan?.id || ''}
                />
              )}

              {activeTab === 'reports' && activeScan && (
                <ReportsViewer scan={activeScan} />
              )}

              {activeTab === 'reports' && !activeScan && (
                <div className="p-12 text-center text-slate-500 font-mono text-xs border border-slate-800 rounded-xl">
                  Run a scan to generate and view markdown reports, summaries, and logs.
                </div>
              )}
            </div>
          </div>

          <div className="lg:col-span-1 h-[520px]">
            <HistorySidebar
              scans={scansList}
              currentScanId={activeScan?.id || ''}
              onSelectScan={(id) => {
                fetchScanDetails(id);
              }}
            />
          </div>
        </div>
      </main>
    </div>
  );
}
