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
  Layers,
  AlertTriangle,
  Server
} from 'lucide-react';
import { TerminalLog } from './TerminalLog';
import { ReportsViewer } from './ReportsViewer';
import { TopologyGraph } from './TopologyGraph';
import { RiskScanner } from './RiskScanner';

export const ResultsView = ({ scan, onNewScan, defaultTab = 'topology' }) => {
  const [activeTab, setActiveTab] = useState(defaultTab); // 'topology' | 'alive' | 'risk' | 'all' | 'reports' | 'terminal'
  const [copiedUrl, setCopiedUrl] = useState(null);
  const [search, setSearch] = useState('');
  const [copiedAll, setCopiedAll] = useState(false);
  const [hostCategoryFilter, setHostCategoryFilter] = useState('all'); // 'all' | 'http' | 'dns' | 'blocked'

  if (!scan) return null;

  const aliveHosts = scan.aliveHosts || [];
  const allSubdomains = scan.subdomains || [];
  const httpHosts = scan.httpHosts || aliveHosts.filter((h) => h.hostType === 'http' || (h.statusCode > 0 && !h.ssrfBlocked));
  const dnsHosts = scan.dnsHosts || aliveHosts.filter((h) => h.hostType === 'dns' || (h.statusCode === 0 && !h.ssrfBlocked));
  const blockedHosts = scan.blockedHosts || aliveHosts.filter((h) => h.hostType === 'blocked' || h.ssrfBlocked);

  const httpCount = scan.httpCount !== undefined ? scan.httpCount : httpHosts.length;
  const dnsCount = scan.dnsCount !== undefined ? scan.dnsCount : dnsHosts.length;
  const blockedCount = scan.blockedCount !== undefined ? scan.blockedCount : blockedHosts.length;

  const filteredAlive = aliveHosts.filter((h) => {
    if (hostCategoryFilter === 'http' && (h.hostType !== 'http' && !(h.statusCode > 0 && !h.ssrfBlocked))) return false;
    if (hostCategoryFilter === 'dns' && (h.hostType !== 'dns' && !(h.statusCode === 0 && !h.ssrfBlocked))) return false;
    if (hostCategoryFilter === 'blocked' && (h.hostType !== 'blocked' && !h.ssrfBlocked)) return false;

    if (!search) return true;
    const q = search.toLowerCase();
    const matchUrl = h.url.toLowerCase().includes(q);
    const matchTitle = (h.title || '').toLowerCase().includes(q);
    const matchIp = (h.ip || '').toLowerCase().includes(q);
    const matchTech = (h.techStack || []).some((t) => t.toLowerCase().includes(q));
    return matchUrl || matchTitle || matchIp || matchTech;
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
    <div className="max-w-6xl mx-auto py-6 px-4 space-y-5 animate-fade-in">
      {/* Top Results Summary Bar */}
      <div className="bg-[#161822] border border-[#262b3b] rounded-2xl p-5 sm:p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-1.5">
          <div className="inline-flex items-center space-x-1.5 text-xs font-semibold text-emerald-400">
            <ShieldCheck className="w-4 h-4" />
            <span>Reconnaissance Complete</span>
          </div>

          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center space-x-2">
            <span>Target:</span>
            <span className="text-indigo-400 font-mono">{scan.domain}</span>
          </h2>

          <div className="flex flex-wrap items-center gap-2 sm:gap-3 text-xs text-slate-400 pt-1">
            <span>
              <strong className="text-white font-mono">{allSubdomains.length}</strong> subdomains
            </span>
            <span>·</span>
            <span className="inline-flex items-center space-x-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block"></span>
              <span><strong className="text-emerald-400 font-mono">{httpCount}</strong> HTTP live</span>
            </span>
            <span>·</span>
            <span className="inline-flex items-center space-x-1">
              <span className="w-2 h-2 rounded-full bg-sky-400 inline-block"></span>
              <span><strong className="text-sky-400 font-mono">{dnsCount}</strong> DNS only</span>
            </span>
            {blockedCount > 0 && (
              <>
                <span>·</span>
                <span className="inline-flex items-center space-x-1">
                  <span className="w-2 h-2 rounded-full bg-rose-400 inline-block"></span>
                  <span><strong className="text-rose-400 font-mono">{blockedCount}</strong> blocked internal</span>
                </span>
              </>
            )}
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

      {/* Clean Tab Bar with Visual Icons */}
      <div className="flex border-b border-[#232733] space-x-1 sm:space-x-2 overflow-x-auto text-xs sm:text-sm font-medium">
        <button
          onClick={() => setActiveTab('topology')}
          className={`pb-3 px-3 sm:px-4 flex items-center space-x-2 border-b-2 whitespace-nowrap transition-colors ${
            activeTab === 'topology'
              ? 'border-indigo-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4 text-indigo-400" />
          <span>Topology Graph</span>
        </button>

        <button
          onClick={() => { setActiveTab('alive'); setSearch(''); setHostCategoryFilter('all'); }}
          className={`pb-3 px-3 sm:px-4 flex items-center space-x-2 border-b-2 whitespace-nowrap transition-colors ${
            activeTab === 'alive'
              ? 'border-indigo-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4 text-emerald-400" />
          <span>Live Websites ({httpCount})</span>
        </button>

        <button
          onClick={() => setActiveTab('risk')}
          className={`pb-3 px-3 sm:px-4 flex items-center space-x-2 border-b-2 whitespace-nowrap transition-colors ${
            activeTab === 'risk'
              ? 'border-amber-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span>Risk & HVTs</span>
        </button>

        <button
          onClick={() => { setActiveTab('all'); setSearch(''); }}
          className={`pb-3 px-3 sm:px-4 flex items-center space-x-2 border-b-2 whitespace-nowrap transition-colors ${
            activeTab === 'all'
              ? 'border-indigo-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Globe className="w-4 h-4 text-cyan-400" />
          <span>All Subdomains ({allSubdomains.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('reports')}
          className={`pb-3 px-3 sm:px-4 flex items-center space-x-2 border-b-2 whitespace-nowrap transition-colors ${
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
          className={`pb-3 px-3 sm:px-4 flex items-center space-x-2 border-b-2 whitespace-nowrap transition-colors ${
            activeTab === 'terminal'
              ? 'border-indigo-500 text-white font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-4 h-4 text-slate-400" />
          <span>Terminal Log</span>
        </button>
      </div>

      {/* TAB 1: Visual Topology Graph */}
      {activeTab === 'topology' && (
        <TopologyGraph scan={scan} />
      )}

      {/* TAB 2: Live Websites with Tech Stack Fingerprints */}
      {activeTab === 'alive' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search hosts, titles, IP, or tech (e.g. Nginx, Cloudflare)..."
                className="w-full pl-9 pr-3 py-2 bg-[#161822] border border-[#262b3b] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono"
              />
            </div>

            <a
              href={`/api/recon/download/${scan.id}/alive`}
              className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center space-x-1.5 self-start sm:self-center font-mono"
              download
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export alive.txt ({httpCount})</span>
            </a>
          </div>

          {/* Sub-category Filter Chips */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <button
              onClick={() => setHostCategoryFilter('all')}
              className={`px-2.5 py-1 rounded-lg border transition-colors ${
                hostCategoryFilter === 'all'
                  ? 'bg-slate-700 text-white border-slate-500 font-semibold'
                  : 'bg-[#161822] text-slate-400 border-[#262b3b] hover:text-slate-200'
              }`}
            >
              All Resolved ({aliveHosts.length})
            </button>
            <button
              onClick={() => setHostCategoryFilter('http')}
              className={`px-2.5 py-1 rounded-lg border transition-colors ${
                hostCategoryFilter === 'http'
                  ? 'bg-emerald-600 text-white border-emerald-500 font-semibold'
                  : 'bg-[#161822] text-emerald-400/80 border-[#262b3b] hover:text-emerald-300'
              }`}
            >
              HTTP Live ({httpCount})
            </button>
            <button
              onClick={() => setHostCategoryFilter('dns')}
              className={`px-2.5 py-1 rounded-lg border transition-colors ${
                hostCategoryFilter === 'dns'
                  ? 'bg-sky-600 text-white border-sky-500 font-semibold'
                  : 'bg-[#161822] text-sky-400/80 border-[#262b3b] hover:text-sky-300'
              }`}
            >
              DNS Only ({dnsCount})
            </button>
            {blockedCount > 0 && (
              <button
                onClick={() => setHostCategoryFilter('blocked')}
                className={`px-2.5 py-1 rounded-lg border transition-colors ${
                  hostCategoryFilter === 'blocked'
                    ? 'bg-rose-600 text-white border-rose-500 font-semibold'
                    : 'bg-[#161822] text-rose-400/80 border-[#262b3b] hover:text-rose-300'
                }`}
              >
                Blocked Internal ({blockedCount})
              </button>
            )}
          </div>

          {filteredAlive.length === 0 ? (
            <div className="p-12 text-center text-slate-500 bg-[#161822] border border-[#262b3b] rounded-2xl text-sm font-mono">
              // No live websites match your filter.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              {filteredAlive.map((host, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl bg-[#161822] border border-[#262b3b] hover:border-slate-700 transition-all space-y-3 flex flex-col justify-between"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center space-x-1.5">
                        {host.hostType === 'blocked' || host.ssrfBlocked ? (
                          <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30">
                            SSRF Blocked
                          </span>
                        ) : host.hostType === 'http' || host.statusCode > 0 ? (
                          <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            {host.statusCode} OK
                          </span>
                        ) : (
                          <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded-full bg-sky-500/10 text-sky-400 border border-sky-500/20">
                            DNS Only
                          </span>
                        )}
                        {host.takeoverRisk && host.takeoverRisk.isVulnerable && (
                          <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            Takeover Risk
                          </span>
                        )}
                      </div>

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

                    {/* Detected Tech Stack Badges */}
                    {host.techStack && host.techStack.length > 0 && (
                      <div className="flex flex-wrap gap-1 pt-1">
                        {host.techStack.map((tech, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded-md bg-[#0e1017] text-indigo-300 border border-[#262b3b] text-[10px] font-mono font-medium"
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="pt-2 border-t border-[#202533] flex items-center justify-between text-xs text-slate-500">
                    <span className="font-mono text-[11px]">
                      {host.ip ? `IP: ${host.ip}` : host.server ? `Server: ${host.server}` : 'Direct Web'}
                    </span>

                    <button
                      onClick={() => handleCopy(host.url, `host_${idx}`)}
                      className="flex items-center space-x-1 text-slate-400 hover:text-white px-2 py-1 rounded bg-[#0e1017] border border-[#202533] text-[11px] font-mono"
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

      {/* TAB 3: Risk & High-Value Targets Scanner */}
      {activeTab === 'risk' && (
        <RiskScanner scan={scan} />
      )}

      {/* TAB 4: All Subdomains List */}
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
                className="w-full pl-9 pr-3 py-2 bg-[#0e1017] border border-[#262b3b] rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono"
              />
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={handleCopyAllSubs}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-300 hover:text-white bg-[#0e1017] border border-[#262b3b] flex items-center space-x-1.5 transition-colors font-mono"
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
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-indigo-400 hover:text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 flex items-center space-x-1.5 transition-colors font-mono"
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

      {/* TAB 5: Reports & Artifacts */}
      {activeTab === 'reports' && (
        <ReportsViewer scan={scan} />
      )}

      {/* TAB 6: Raw Terminal Output */}
      {activeTab === 'terminal' && (
        <div className="space-y-3">
          <div className="text-xs text-slate-400 font-mono">
            // Raw output log from the 6-step reconnaissance pipeline:
          </div>
          <TerminalLog logs={scan.logs || []} isScanning={false} />
        </div>
      )}
    </div>
  );
};
