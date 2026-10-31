import React, { useState } from 'react';
import { FileText, Download, Copy, Check, FileCode, Shield } from 'lucide-react';

export const ReportsViewer = ({ scan }) => {
  const [activeTab, setActiveTab] = useState('report');
  const [copied, setCopied] = useState(false);

  if (!scan) return null;

  const getActiveContent = () => {
    switch (activeTab) {
      case 'report':
        return scan.files?.reportMd || '// Report will be compiled upon stage 6 completion.';
      case 'summary':
        return scan.files?.summaryTxt || '// Summary will be compiled upon stage 6 completion.';
      case 'log':
        return scan.files?.reconLog || '// Audit log will be flushed upon stage 6 completion.';
      case 'subdomains':
        return scan.files?.subdomainsTxt || (scan.subdomains || []).join('\n') || '// No subdomains.';
      case 'alive':
        return scan.files?.aliveTxt || (scan.aliveHosts || []).map((h) => h.url).join('\n') || '// No live hosts.';
      default:
        return '';
    }
  };

  const getDownloadRoute = () => {
    return `/api/recon/download/${scan.id}/${activeTab}`;
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(getActiveContent());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const tabs = [
    { id: 'report', label: 'report.md', icon: FileText },
    { id: 'summary', label: 'summary.txt', icon: FileCode },
    { id: 'log', label: 'recon.log', icon: Shield },
    { id: 'subdomains', label: 'subdomains.txt', icon: FileText },
    { id: 'alive', label: 'alive.txt', icon: FileText },
  ];

  return (
    <div className="rounded-xl border border-[#1a1f2c] bg-[#090b10] overflow-hidden shadow-xl flex flex-col h-full min-h-[500px]">
      {/* Tab navigation */}
      <div className="p-2.5 bg-[#0c0f16] border-b border-[#181c26] flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-1 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-colors flex items-center space-x-1.5 ${
                  isActive
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`}
              >
                <Icon className="w-3 h-3" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleCopy}
            className="flex items-center space-x-1 text-xs font-mono text-slate-300 hover:text-white px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 transition-colors"
          >
            {copied ? (
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

          <a
            href={getDownloadRoute()}
            className="flex items-center space-x-1 text-xs font-mono text-emerald-400 hover:text-emerald-300 px-2.5 py-1 rounded-lg bg-emerald-950/40 hover:bg-emerald-900/40 border border-emerald-800/50 transition-colors"
            download
          >
            <Download className="w-3 h-3" />
            <span className="text-[10px]">Download</span>
          </a>
        </div>
      </div>

      {/* Artifact Content Preview */}
      <div className="flex-1 overflow-auto p-4 font-mono text-xs text-slate-300 bg-[#07090e] select-text whitespace-pre leading-relaxed scanline">
        {getActiveContent()}
      </div>
    </div>
  );
};
