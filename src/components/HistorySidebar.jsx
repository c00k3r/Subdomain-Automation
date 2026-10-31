import React from 'react';
import { History, Globe, Clock, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';

export const HistorySidebar = ({ scans = [], currentScanId = '', onSelectScan }) => {
  return (
    <div className="rounded-xl border border-[#1a1f2c] bg-[#090b10] overflow-hidden shadow-xl flex flex-col h-full">
      <div className="p-3 bg-[#0c0f16] border-b border-[#181c26] flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <History className="w-3.5 h-3.5 text-emerald-400" />
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
            Past Missions
          </h3>
        </div>
        <span className="text-[10px] font-mono text-slate-500 bg-[#07090e] px-1.5 py-0.5 rounded border border-slate-800">
          {scans.length}
        </span>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-[#151923]">
        {scans.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-600 font-mono">
            // No prior scan runs recorded.
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
                    ? 'bg-emerald-950/20 border-l-2 border-emerald-500'
                    : 'hover:bg-[#0e121b]'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center space-x-1.5 overflow-hidden">
                    <Globe className="w-3 h-3 text-slate-500 flex-shrink-0" />
                    <span className="text-xs font-mono font-medium text-slate-200 truncate">
                      {s.domain}
                    </span>
                  </div>

                  {s.status === 'running' && (
                    <Loader2 className="w-3 h-3 text-emerald-400 animate-spin flex-shrink-0" />
                  )}
                  {s.status === 'completed' && (
                    <CheckCircle2 className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                  )}
                  {s.status === 'failed' && (
                    <AlertCircle className="w-3 h-3 text-rose-400 flex-shrink-0" />
                  )}
                </div>

                <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                  <span>
                    {s.totalSubdomains} assets · {s.aliveCount} live
                  </span>
                  {s.executionTime && (
                    <span className="flex items-center space-x-1 text-slate-500">
                      <Clock className="w-2.5 h-2.5" />
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
