import React, { useState } from 'react';
import { Search, Copy, Check, Download, ExternalLink, Globe, Layers } from 'lucide-react';

export const SubdomainsTable = ({ subdomains = [], domain = '', scanId = '' }) => {
  const [search, setSearch] = useState('');
  const [copied, setCopied] = useState(false);

  const filtered = subdomains.filter((sub) => {
    if (!search) return true;
    return sub.toLowerCase().includes(search.toLowerCase());
  });

  const handleCopyAll = () => {
    navigator.clipboard.writeText(subdomains.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(subdomains, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${domain}_subdomains.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="rounded-xl border border-[#1a1f2c] bg-[#090b10] overflow-hidden shadow-xl flex flex-col h-full min-h-[500px]">
      {/* Control Header */}
      <div className="p-3 bg-[#0c0f16] border-b border-[#181c26] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-semibold text-slate-200 tracking-wide uppercase font-mono">
            Enumerated Targets
          </h3>
          <span className="text-[11px] font-mono text-cyan-400">
            [{filtered.length} / {subdomains.length}]
          </span>
        </div>

        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="w-3 h-3 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Filter by prefix..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="text-xs font-mono bg-[#07090e] border border-slate-800 rounded-lg pl-7 pr-3 py-1 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 w-36 sm:w-48"
            />
          </div>

          <button
            onClick={handleCopyAll}
            className="flex items-center space-x-1 text-xs font-mono text-slate-300 hover:text-white px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 transition-colors"
            title="Copy all subdomains to clipboard"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400 text-[10px]">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span className="text-[10px]">Copy All</span>
              </>
            )}
          </button>

          <button
            onClick={handleExportJSON}
            className="hidden sm:flex items-center space-x-1 text-xs font-mono text-slate-300 hover:text-white px-2 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 transition-colors text-[10px]"
            title="Export as JSON"
          >
            JSON
          </button>

          <a
            href={`/api/recon/download/${scanId}/subdomains`}
            className="flex items-center space-x-1 text-xs font-mono text-cyan-400 hover:text-cyan-300 px-2.5 py-1 rounded-lg bg-cyan-950/40 hover:bg-cyan-900/40 border border-cyan-800/50 transition-colors"
            download
            title="Download subdomains.txt"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">subdomains.txt</span>
          </a>
        </div>
      </div>

      {/* Subdomain Rows */}
      <div className="flex-1 overflow-y-auto divide-y divide-[#151923] font-mono text-xs">
        {filtered.length === 0 ? (
          <div className="p-10 text-center text-slate-600">
            {subdomains.length === 0
              ? '// No subdomains enumerated yet.'
              : '// No subdomains match your search query.'}
          </div>
        ) : (
          filtered.map((sub, idx) => {
            const prefix = sub.endsWith(`.${domain}`)
              ? sub.replace(`.${domain}`, '')
              : sub === domain
              ? '@ (apex)'
              : sub;

            return (
              <div
                key={idx}
                className="px-3.5 py-2 hover:bg-[#0e121b] flex items-center justify-between group transition-colors"
              >
                <div className="flex items-center space-x-3 overflow-hidden">
                  <span className="text-slate-600 w-7 text-right select-none font-mono text-[10px]">
                    {idx + 1}
                  </span>
                  <span className="text-slate-200 select-all font-medium truncate">
                    {sub}
                  </span>
                  <span className="text-[10px] text-slate-500 bg-[#07090e] px-1.5 py-0.5 rounded border border-slate-800/80 hidden sm:inline-block">
                    {prefix}
                  </span>
                </div>

                <div className="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => navigator.clipboard.writeText(sub)}
                    className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded"
                    title="Copy domain"
                  >
                    <Copy className="w-3 h-3" />
                  </button>
                  <a
                    href={`https://${sub}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-1 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded"
                    title="Probe in browser"
                  >
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
