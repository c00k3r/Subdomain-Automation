import React, { useState } from 'react';
import {
  Globe,
  Activity,
  FileText,
  Terminal,
  ExternalLink,
  Copy,
  Check,
  Download,
  Search,
  Clock,
  RotateCcw,
  ShieldCheck,
  Share2
} from 'lucide-react';
import { TerminalLog } from './TerminalLog';
import { ReportsViewer } from './ReportsViewer';

export const ResultsView = ({ scan, onNewScan, defaultTab = 'reports' }) => {
  const [activeTab, setActiveTab] = useState(defaultTab); // 'reports' | 'alive' | 'all' | 'terminal'
  const [copiedUrl, setCopiedUrl] = useState(null);
  const [search, setSearch] = useState('');
  const [copiedAll, setCopiedAll] = useState(false);

  if (!scan) return null;

  const aliveHosts = scan.aliveHosts || [];
  const allSubdomains = scan.subdomains || [];

  const filteredAlive = aliveHosts.filter((h) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      h.url.toLowerCase().includes(q) ||
      (h.title || '').toLowerCase().includes(q) ||
      (h.ip || '').toLowerCase().includes(q)
    );
  });

  const filteredSubs = allSubdomains.filter((s) => {
    if (!search) return true;
    return s.toLowerCase().includes(search.toLowerCase());
  });

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedUrl(id);
    setTimeout(() => setCopiedUrl(null), 1800);
  };

  const handleCopyAllSubs = () => {
    navigator.clipboard.writeText(allSubdomains.join('\n'));
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  return (
    <div className="max-w-5xl mx-auto py-6 px-4 space-y-6 animate-fade-in">
      {/* Top Results Summary Bar */}
      <div className="bg-[#161822] border border-[#262b3b] rounded-2xl p-5 sm:p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-1.5">
          <div className="inline-flex items-center space-x-1.5 text-xs font-semibold text-emerald-400">
            <ShieldCheck className="w-4 h-4" />
            <span>Scan Completed Successfully</span>
          </div>

          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center space-x-2">
            <span>Results for</span>
            <span className="text-indigo-400 font-mono">{scan.domain}</span>
          </h2>

          <div className="flex items-center space-x-3 text-xs text-slate-400 pt-1">
            <span>
              <strong className="text-white font-mono">{allSubdomains.length}</strong> subdomains
            </span>
            <span>·</span>
            <span>
              <strong className="text-emerald-400 font-mono">{aliveHosts.length}</strong> live hosts
            </span>
            <span>·</span>
            <span className="flex items-center space-x-1">
              <Clock className="w-3.5 h-3.5" />
              <span>{scan.executionTime || 0}s</span>
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <a
            href={`/api/recon/download/${scan.id}/report`}
            className="px-4 py-2.5 rounded-xl text-xs font-semibold text-slate-200 bg-[#0e1017] hover:bg-[#1a1d29] border border-[#262b3b] transition-all flex items-center space-x-1.5 shadow-sm"
            download
          >
            <Download className="w-4 h-4 text-indigo-400" />
            <span>Download Report</span>
          </a>

          <button
            onClick={onNewScan}
            className="px-4 py-2.5 rounded-xl text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 transition-all flex items-center space-x-1.5 shadow-lg shadow-indigo-600/25"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </button>
        </div>
      </div>

      {/* Clean Tab Bar */}
      <div className="flex border-b border-[#232733] space-x-2 overflow-x-auto text-sm font-medium">
        <button
          onClick={() => { setActiveTab('alive'); setSearch(''); }}
          className={`pb-3 px-4 flex items-center space-x-2 border-b-2 transition-colors ${
            activeTab === 'alive'
              ? 'border-indigo-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4 text-emerald-400" />
          <span>Live Websites ({aliveHosts.length})</span>
        </button>

        <button
          onClick={() => { setActiveTab('all'); setSearch(''); }}
          className={`pb-3 px-4 flex items-center space-x-2 border-b-2 transition-colors ${
            activeTab === 'all'
              ? 'border-indigo-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Globe className="w-4 h-4 text-indigo-400" />
          <span>All Subdomains ({allSubdomains.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('reports')}
          className={`pb-3 px-4 flex items-center space-x-2 border-b-2 transition-colors ${
            activeTab === 'reports'
              ? 'border-indigo-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="w-4 h-4 text-slate-400" />
          <span>Reports & Files</span>
        </button>

        <button
          onClick={() => setActiveTab('terminal')}
          className={`pb-3 px-4 flex items-center space-x-2 border-b-2 transition-colors ${
            activeTab === 'terminal'
              ? 'border-indigo-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-4 h-4 text-slate-400" />
          <span>Terminal Output</span>
        </button>
      </div>

      {/* TAB 1: Live Websites Cards */}
      {activeTab === 'alive' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search live hosts, titles, or IP..."
                className="w-full pl-9 pr-3 py-2 bg-[#161822] border border-[#262b3b] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <a
              href={`/api/recon/download/${scan.id}/alive`}
              className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center space-x-1.5 self-start sm:self-center"
              download
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export alive.txt</span>
            </a>
          </div>

          {filteredAlive.length === 0 ? (
            <div className="p-12 text-center text-slate-500 bg-[#161822] border border-[#262b3b] rounded-2xl text-sm">
              No live websites found matching your search.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              {filteredAlive.map((host, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl bg-[#161822] border border-[#262b3b] hover:border-slate-700 transition-all space-y-3 flex flex-col justify-between"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {host.statusCode ? `${host.statusCode} OK` : 'DNS Active'}
                      </span>
                      <span className="text-[11px] text-slate-500 font-mono">
                        {host.latencyMs}ms
                      </span>
                    </div>

                    <a
                      href={host.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-sm font-semibold text-white hover:text-indigo-400 transition-colors flex items-center space-x-1.5 truncate"
                    >
                      <span className="truncate">{host.url}</span>
                      <ExternalLink className="w-3.5 h-3.5 shrink-0 opacity-60" />
                    </a>

                    {host.title && (
                      <p className="text-xs text-slate-400 line-clamp-1 italic">
                        "{host.title}"
                      </p>
                    )}
                  </div>

                  <div className="pt-2 border-t border-[#202533] flex items-center justify-between text-xs text-slate-500">
                    <span className="font-mono text-[11px]">
                      {host.ip ? `IP: ${host.ip}` : host.server ? `Server: ${host.server}` : 'Direct Web'}
                    </span>

                    <button
                      onClick={() => handleCopy(host.url, `host_${idx}`)}
                      className="flex items-center space-x-1 text-slate-400 hover:text-white px-2 py-1 rounded bg-[#0e1017] border border-[#202533] text-[11px]"
                    >
                      {copiedUrl === `host_${idx}` ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy URL</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: All Subdomains List */}
      {activeTab === 'all' && (
        <div className="bg-[#161822] border border-[#262b3b] rounded-2xl overflow-hidden shadow-xl">
          <div className="p-4 border-b border-[#232733] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter subdomains..."
                className="w-full pl-9 pr-3 py-2 bg-[#0e1017] border border-[#262b3b] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={handleCopyAllSubs}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-300 hover:text-white bg-[#0e1017] border border-[#262b3b] flex items-center space-x-1.5 transition-colors"
              >
                {copiedAll ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">All Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy All</span>
                  </>
                )}
              </button>

              <a
                href={`/api/recon/download/${scan.id}/subdomains`}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-indigo-400 hover:text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 flex items-center space-x-1.5 transition-colors"
                download
              >
                <Download className="w-3.5 h-3.5" />
                <span>subdomains.txt</span>
              </a>
            </div>
          </div>

          <div className="divide-y divide-[#202533] max-h-[500px] overflow-y-auto font-mono text-xs">
            {filteredSubs.length === 0 ? (
              <div className="p-8 text-center text-slate-500">
                No subdomains match your search.
              </div>
            ) : (
              filteredSubs.map((sub, idx) => (
                <div
                  key={idx}
                  className="px-4 py-2.5 hover:bg-[#12141c] flex items-center justify-between group transition-colors"
                >
                  <div className="flex items-center space-x-3 overflow-hidden">
                    <span className="text-slate-600 w-8 select-none text-[11px]">
                      {idx + 1}.
                    </span>
                    <span className="text-slate-200 font-medium truncate select-all">
                      {sub}
                    </span>
                  </div>

                  <div className="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={() => handleCopy(sub, `sub_${idx}`)}
                      className="p-1 text-slate-400 hover:text-white"
                      title="Copy subdomain"
                    >
                      {copiedUrl === `sub_${idx}` ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                    <a
                      href={`https://${sub}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-1 text-slate-400 hover:text-indigo-400"
                      title="Open in new tab"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 3: Reports & Artifacts */}
      {activeTab === 'reports' && (
        <ReportsViewer scan={scan} />
      )}

      {/* TAB 4: Raw Terminal Output */}
      {activeTab === 'terminal' && (
        <div className="space-y-3">
          <div className="text-xs text-slate-400">
            Raw output log from the 6-step reconnaissance pipeline:
          </div>
          <TerminalLog logs={scan.logs || []} isScanning={false} />
        </div>
      )}
    </div>
  );
};
