import React, { useState } from 'react';
import { ExternalLink, Copy, Check, Download, Activity } from 'lucide-react';

export const LiveHostsTable = ({ aliveHosts = [], scanId = '' }) => {
  const [copied, setCopied] = useState(false);
  const [filterCode, setFilterCode] = useState('all');

  const filtered = aliveHosts.filter((host) => {
    if (filterCode === 'all') return true;
    if (filterCode === '2xx') return host.statusCode >= 200 && host.statusCode < 300;
    if (filterCode === '3xx') return host.statusCode >= 300 && host.statusCode < 400;
    if (filterCode === '4xx') return host.statusCode >= 400 && host.statusCode < 500;
    if (filterCode === '5xx') return host.statusCode >= 500;
    if (filterCode === 'dns') return host.statusCode === 0;
    return true;
  });

  const handleCopyAll = () => {
    navigator.clipboard.writeText(aliveHosts.map((h) => h.url).join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStatusBadge = (code) => {
    if (code >= 200 && code < 300) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
          {code} OK
        </span>
      );
    }
    if (code >= 300 && code < 400) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30">
          {code} REDIR
        </span>
      );
    }
    if (code >= 400 && code < 500) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">
          {code} CLIENT
        </span>
      );
    }
    if (code >= 500) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30">
          {code} ERROR
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-400 border border-slate-700">
        DNS ONLY
      </span>
    );
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden shadow-lg flex flex-col h-[520px]">
      <div className="p-3.5 bg-slate-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <Activity className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-slate-200">
            Live Hosts Detected (Httpx)
          </h3>
          <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-emerald-950/80 text-emerald-300 border border-emerald-800/60">
            {filtered.length} of {aliveHosts.length} alive
          </span>
        </div>

        <div className="flex items-center space-x-2">
          <select
            value={filterCode}
            onChange={(e) => setFilterCode(e.target.value)}
            className="text-xs bg-slate-950 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="all">All Status Codes</option>
            <option value="2xx">2xx Success</option>
            <option value="3xx">3xx Redirect</option>
            <option value="4xx">4xx Client Error</option>
            <option value="5xx">5xx Server Error</option>
            <option value="dns">DNS Only</option>
          </select>

          <button
            onClick={handleCopyAll}
            className="flex items-center space-x-1 text-xs text-slate-300 hover:text-white px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors"
            title="Copy all alive URLs"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy</span>
              </>
            )}
          </button>

          <a
            href={`/api/recon/download/${scanId}/alive`}
            className="flex items-center space-x-1 text-xs text-emerald-300 hover:text-emerald-100 px-2.5 py-1.5 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-800/60 transition-colors"
            download
            title="Download alive.txt"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">alive.txt</span>
          </a>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 font-mono text-xs">
        {filtered.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            {aliveHosts.length === 0
              ? 'No live hosts identified yet. Httpx probe runs in Step 5.'
              : 'No hosts match your selected status code filter.'}
          </div>
        ) : (
          filtered.map((host, i) => (
            <div
              key={i}
              className="px-4 py-3 hover:bg-slate-800/40 flex flex-col sm:flex-row sm:items-center justify-between gap-2 group transition-colors"
            >
              <div className="space-y-1 min-w-0">
                <div className="flex items-center space-x-2">
                  {getStatusBadge(host.statusCode)}
                  <a
                    href={host.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium text-emerald-400 hover:underline flex items-center space-x-1 truncate"
                  >
                    <span>{host.url}</span>
                    <ExternalLink className="w-3 h-3 flex-shrink-0 opacity-70" />
                  </a>
                  <span className="text-[11px] text-slate-400 font-mono bg-slate-800/80 px-1.5 py-0.5 rounded">
                    {host.latencyMs}ms
                  </span>
                </div>

                <div className="flex items-center space-x-3 text-[11px] text-slate-400">
                  {host.ip && (
                    <span className="text-slate-400">
                      IP: <span className="text-slate-300">{host.ip}</span>
                    </span>
                  )}
                  {host.server && (
                    <span className="text-slate-400">
                      Server: <span className="text-slate-300">{host.server}</span>
                    </span>
                  )}
                  {host.title && (
                    <span className="text-slate-300 truncate max-w-md italic">
                      "{host.title}"
                    </span>
                  )}
                </div>
              </div>

              <div className="flex items-center space-x-2 self-end sm:self-center">
                <button
                  onClick={() => navigator.clipboard.writeText(host.url)}
                  className="px-2 py-1 text-slate-400 hover:text-slate-200 hover:bg-slate-700/60 rounded border border-transparent hover:border-slate-600 transition-colors"
                  title="Copy URL"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
