import React from 'react';
import { History, Globe, Clock, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';

export const HistorySidebar = ({ scans = [], currentScanId = '', onSelectScan }) => {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden shadow-lg flex flex-col h-full">
      <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <History className="w-4 h-4 text-blue-400" />
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
            Recon History
          </h3>
        </div>
        <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded-full">
          {scans.length}
        </span>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-slate-800/50">
        {scans.length === 0 ? (
          <div className="p-4 text-center text-xs text-slate-500">
            No scan history yet.
          </div>
        ) : (
          scans.map((s) => {
            const isSelected = s.id === currentScanId;
            return (
              <button
                key={s.id}
                onClick={() => onSelectScan(s.id)}
                className={`w-full text-left p-3 transition-colors ${
                  isSelected
                    ? 'bg-blue-950/40 border-l-2 border-blue-500'
                    : 'hover:bg-slate-800/30'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center space-x-1.5 overflow-hidden">
                    <Globe className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
                    <span className="text-xs font-medium text-slate-200 truncate">
                      {s.domain}
                    </span>
                  </div>

                  {s.status === 'running' && (
                    <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin flex-shrink-0" />
                  )}
                  {s.status === 'completed' && (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                  )}
                  {s.status === 'failed' && (
                    <AlertCircle className="w-3.5 h-3.5 text-rose-400 flex-shrink-0" />
                  )}
                </div>

                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <span>
                    {s.totalSubdomains} subs / {s.aliveCount} alive
                  </span>
                  {s.executionTime && (
                    <span className="flex items-center space-x-1 text-slate-500">
                      <Clock className="w-3 h-3" />
                      <span>{s.executionTime}s</span>
                    </span>
                  )}
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
};
