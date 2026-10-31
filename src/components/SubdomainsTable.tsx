import React, { useState } from 'react';
import { Search, Copy, Check, Download, ExternalLink, Globe } from 'lucide-react';

interface Props {
  subdomains: string[];
  domain: string;
  scanId: string;
}

export const SubdomainsTable: React.FC<Props> = ({ subdomains, domain, scanId }) => {
  const [search, setSearch] = useState('');
  const [copied, setCopied] = useState(false);

  const filtered = subdomains.filter((sub) =>
    sub.toLowerCase().includes(search.toLowerCase())
  );

  const handleCopyAll = () => {
    navigator.clipboard.writeText(subdomains.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden shadow-lg flex flex-col h-[520px]">
      <div className="p-3.5 bg-slate-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-200">
            Discovered Subdomains
          </h3>
          <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
            {filtered.length} of {subdomains.length}
          </span>
        </div>

        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Filter subdomains..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="text-xs bg-slate-950 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-44 sm:w-56"
            />
          </div>

          <button
            onClick={handleCopyAll}
            className="flex items-center space-x-1 text-xs text-slate-300 hover:text-white px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors"
            title="Copy all subdomains"
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
            href={`/api/recon/download/${scanId}/subdomains`}
            className="flex items-center space-x-1 text-xs text-cyan-300 hover:text-cyan-100 px-2.5 py-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800/60 transition-colors"
            download
            title="Download subdomains.txt"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">subdomains.txt</span>
          </a>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 font-mono text-xs">
        {filtered.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            {subdomains.length === 0
              ? 'No subdomains discovered yet.'
              : 'No subdomains match your filter.'}
          </div>
        ) : (
          filtered.map((sub, i) => {
            const prefix = sub.endsWith(`.${domain}`)
              ? sub.replace(`.${domain}`, '')
              : sub === domain
              ? '@ (root)'
              : sub;

            return (
              <div
                key={i}
                className="px-4 py-2 hover:bg-slate-800/40 flex items-center justify-between group transition-colors"
              >
                <div className="flex items-center space-x-3 overflow-hidden">
                  <span className="text-slate-600 w-8 text-right select-none font-mono text-[11px]">
                    {i + 1}
                  </span>
                  <span className="text-slate-200 font-medium truncate select-all">
                    {sub}
                  </span>
                  <span className="text-[10px] text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700/50 hidden sm:inline-block">
                    {prefix}
                  </span>
                </div>

                <div className="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => navigator.clipboard.writeText(sub)}
                    className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded"
                    title="Copy subdomain"
                  >
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                  <a
                    href={`https://${sub}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-1 text-slate-400 hover:text-cyan-400 hover:bg-slate-700 rounded"
                    title="Open in new tab"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
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
