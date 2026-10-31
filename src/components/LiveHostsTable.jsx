import React, { useState } from 'react';
import { ExternalLink, Copy, Check, Download, Activity, Terminal, ShieldAlert } from 'lucide-react';

export const LiveHostsTable = ({ aliveHosts = [], scanId = '' }) => {
  const [copiedUrl, setCopiedUrl] = useState(null);
  const [filterCode, setFilterCode] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  const filtered = aliveHosts.filter((host) => {
    if (filterCode === '2xx' && (host.statusCode < 200 || host.statusCode >= 300)) return false;
    if (filterCode === '3xx' && (host.statusCode < 300 || host.statusCode >= 400)) return false;
    if (filterCode === '4xx' && (host.statusCode < 400 || host.statusCode >= 500)) return false;
    if (filterCode === '5xx' && host.statusCode < 500) return false;
    if (filterCode === 'dns' && host.statusCode !== 0) return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchUrl = host.url.toLowerCase().includes(q);
      const matchTitle = (host.title || '').toLowerCase().includes(q);
      const matchIp = (host.ip || '').toLowerCase().includes(q);
      const matchServer = (host.server || '').toLowerCase().includes(q);
      return matchUrl || matchTitle || matchIp || matchServer;
    }

    return true;
  });

  const handleCopy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedUrl(key);
    setTimeout(() => setCopiedUrl(null), 1800);
  };

  const getStatusBadge = (code) => {
    if (code >= 200 && code < 300) {
      return (
        <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/50">
          {code} OK
        </span>
      );
    }
    if (code >= 300 && code < 400) {
      return (
        <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-sky-950/80 text-sky-400 border border-sky-800/50">
          {code} REDIR
        </span>
      );
    }
    if (code >= 400 && code < 500) {
      return (
        <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800/50">
          {code} CLIENT
        </span>
      );
    }
    if (code >= 500) {
      return (
        <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-rose-950/80 text-rose-400 border border-rose-800/50">
          {code} ERR
        </span>
      );
    }
    return (
      <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
        DNS ONLY
      </span>
    );
  };

  return (
    <div className="rounded-xl border border-[#1a1f2c] bg-[#090b10] overflow-hidden shadow-xl flex flex-col h-full min-h-[500px]">
      {/* Control Toolbar */}
      <div className="p-3 bg-[#0c0f16] border-b border-[#181c26] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <Activity className="w-4 h-4 text-emerald-400" />
          <h3 className="text-xs font-semibold text-slate-200 tracking-wide uppercase font-mono">
            Active Targets (Httpx)
          </h3>
          <span className="text-[11px] font-mono text-emerald-400">
            [{filtered.length} / {aliveHosts.length}]
          </span>
        </div>

        <div className="flex items-center space-x-2">
          <input
            type="text"
            placeholder="Search host, title, IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="text-xs font-mono bg-[#07090e] border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 w-36 sm:w-48"
          />

          <select
            value={filterCode}
            onChange={(e) => setFilterCode(e.target.value)}
            className="text-xs font-mono bg-[#07090e] border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="all">All Status</option>
            <option value="2xx">2xx Success</option>
            <option value="3xx">3xx Redirect</option>
            <option value="4xx">4xx Client</option>
            <option value="5xx">5xx Error</option>
            <option value="dns">DNS Only</option>
          </select>

          <a
            href={`/api/recon/download/${scanId}/alive`}
            className="flex items-center space-x-1 text-xs font-mono text-emerald-400 hover:text-emerald-300 px-2.5 py-1 rounded-lg bg-emerald-950/40 hover:bg-emerald-900/40 border border-emerald-800/50 transition-colors"
            download
            title="Download alive.txt"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">alive.txt</span>
          </a>
        </div>
      </div>

      {/* High-Density Host Rows */}
      <div className="flex-1 overflow-y-auto divide-y divide-[#151923] font-mono text-xs">
        {filtered.length === 0 ? (
          <div className="p-10 text-center text-slate-600">
            {aliveHosts.length === 0
              ? '// No active hosts identified yet. Httpx runs in Stage 5.'
              : '// No hosts match your search criteria.'}
          </div>
        ) : (
          filtered.map((host, idx) => (
            <div
              key={idx}
              className="p-3 hover:bg-[#0e121b] transition-colors flex flex-col md:flex-row md:items-center justify-between gap-2.5 group"
            >
              <div className="space-y-1 min-w-0 flex-1">
                <div className="flex items-center space-x-2.5 flex-wrap">
                  {getStatusBadge(host.statusCode)}

                  <a
                    href={host.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium text-slate-200 hover:text-emerald-400 flex items-center space-x-1 truncate tracking-tight"
                  >
                    <span>{host.url}</span>
                    <ExternalLink className="w-3 h-3 flex-shrink-0 opacity-40 group-hover:opacity-100 transition-opacity" />
                  </a>

                  <span className="text-[10px] text-slate-500 font-mono">
                    {host.latencyMs}ms
                  </span>
                </div>

                <div className="flex items-center space-x-3 text-[11px] text-slate-500 flex-wrap">
                  {host.ip && (
                    <span>
                      IP: <span className="text-slate-400">{host.ip}</span>
                    </span>
                  )}
                  {host.server && (
                    <span>
                      Server: <span className="text-slate-400">{host.server}</span>
                    </span>
                  )}
                  {host.title && (
                    <span className="text-slate-300 italic truncate max-w-sm">
                      "{host.title}"
                    </span>
                  )}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center space-x-2 shrink-0 self-end md:self-center">
                <button
                  onClick={() => handleCopy(host.url, `url_${idx}`)}
                  className="px-2 py-1 text-[11px] text-slate-400 hover:text-slate-200 bg-slate-900/80 hover:bg-slate-800 rounded border border-slate-800 transition-colors flex items-center space-x-1"
                  title="Copy URL"
                >
                  {copiedUrl === `url_${idx}` ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-400 text-[10px]">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span className="text-[10px]">Copy</span>
                    </>
                  )}
                </button>

                <button
                  onClick={() => handleCopy(`curl -I ${host.url}`, `curl_${idx}`)}
                  className="px-2 py-1 text-[11px] text-slate-400 hover:text-slate-200 bg-slate-900/80 hover:bg-slate-800 rounded border border-slate-800 transition-colors flex items-center space-x-1"
                  title="Copy curl -I command"
                >
                  {copiedUrl === `curl_${idx}` ? (
                    <span className="text-emerald-400 text-[10px]">curl copied</span>
                  ) : (
                    <span className="text-[10px] text-slate-400 font-mono">curl</span>
                  )}
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
