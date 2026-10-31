import React, { useState } from 'react';
import { FileText, Download, Copy, Check, FileCode, Shield } from 'lucide-react';

export const ReportsViewer = ({ scan }) => {
  const [activeTab, setActiveTab] = useState('report');
  const [copied, setCopied] = useState(false);

  if (!scan) return null;

  const getActiveContent = () => {
    switch (activeTab) {
      case 'report':
        return scan.files?.reportMd || 'Report will be generated upon scan completion.';
      case 'summary':
        return scan.files?.summaryTxt || 'Summary will be generated upon scan completion.';
      case 'log':
        return scan.files?.reconLog || 'Recon log will be written upon scan completion.';
      case 'subdomains':
        return scan.files?.subdomainsTxt || (scan.subdomains || []).join('\n') || 'No subdomains collected.';
      case 'alive':
        return scan.files?.aliveTxt || (scan.aliveHosts || []).map((h) => h.url).join('\n') || 'No live hosts identified.';
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

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden shadow-lg flex flex-col h-[520px]">
      <div className="p-3 bg-slate-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-1.5 overflow-x-auto">
          <button
            onClick={() => setActiveTab('report')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'report'
                ? 'bg-blue-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>report.md</span>
          </button>

          <button
            onClick={() => setActiveTab('summary')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'summary'
                ? 'bg-blue-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>summary.txt</span>
          </button>

          <button
            onClick={() => setActiveTab('log')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'log'
                ? 'bg-blue-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>recon.log</span>
          </button>

          <button
            onClick={() => setActiveTab('subdomains')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'subdomains'
                ? 'bg-blue-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <span>subdomains.txt</span>
          </button>

          <button
            onClick={() => setActiveTab('alive')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'alive'
                ? 'bg-blue-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <span>alive.txt</span>
          </button>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleCopy}
            className="flex items-center space-x-1 text-xs text-slate-300 hover:text-white px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors"
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
            href={getDownloadRoute()}
            className="flex items-center space-x-1 text-xs text-blue-300 hover:text-white px-2.5 py-1.5 rounded-lg bg-blue-900/60 hover:bg-blue-800/80 border border-blue-700/60 transition-colors"
            download
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download</span>
          </a>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-4 font-mono text-xs text-slate-300 bg-slate-950/70 select-text whitespace-pre leading-relaxed">
        {getActiveContent()}
      </div>
    </div>
  );
};
