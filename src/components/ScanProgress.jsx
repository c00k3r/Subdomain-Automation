import React, { useState } from 'react';
import { Loader2, CheckCircle2, Circle, Terminal, Globe, ChevronDown, ChevronUp } from 'lucide-react';
import { TerminalLog } from './TerminalLog';

const steps = [
  { num: 1, label: 'Checking dependencies & network resolvers' },
  { num: 2, label: 'Querying Certificate Transparency (Subfinder)' },
  { num: 3, label: 'Querying Passive DNS feeds (Assetfinder)' },
  { num: 4, label: 'Merging results & removing duplicates' },
  { num: 5, label: 'Testing live HTTP/HTTPS hosts (Httpx)' },
  { num: 6, label: 'Generating summary & markdown reports' },
];

export const ScanProgress = ({ scan }) => {
  const [showLogs, setShowLogs] = useState(false);

  if (!scan) return null;

  const currentStep = scan.step || 1;
  const progressPercent = Math.min(100, Math.round((currentStep / 6) * 100));

  return (
    <div className="max-w-3xl mx-auto py-10 px-4 space-y-6 animate-fade-in">
      {/* Header status */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-500/10 text-indigo-400 text-xs font-medium">
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
          <span>Reconnaissance in progress</span>
        </div>
        
        <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight flex items-center justify-center space-x-2">
          <span>Scanning</span>
          <span className="text-indigo-400 font-mono">{scan.domain}</span>
        </h2>
        
        <p className="text-slate-400 text-sm">
          Please wait while we gather subdomains and probe active servers...
        </p>
      </div>

      {/* Clean Progress Card */}
      <div className="bg-[#161822] border border-[#262b3b] rounded-2xl p-6 shadow-xl space-y-6">
        {/* Progress Bar */}
        <div className="space-y-2">
          <div className="flex justify-between text-xs font-medium text-slate-400">
            <span>Progress</span>
            <span className="text-indigo-400 font-bold">{progressPercent}%</span>
          </div>
          <div className="h-2.5 w-full bg-[#0e1017] rounded-full overflow-hidden">
            <div
              className="h-full bg-indigo-500 rounded-full transition-all duration-500 ease-out"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>

        {/* Live Counters */}
        <div className="grid grid-cols-2 gap-4 pt-2 border-t border-[#222736]">
          <div className="p-4 rounded-xl bg-[#0e1017] border border-[#202533] text-center">
            <span className="text-xs text-slate-400 font-medium">Subdomains Found</span>
            <div className="text-2xl font-bold text-white font-mono mt-1">
              {scan.totalSubdomains || scan.subdomains?.length || 0}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#0e1017] border border-[#202533] text-center">
            <span className="text-xs text-slate-400 font-medium">Live Websites</span>
            <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">
              {scan.aliveCount || scan.aliveHosts?.length || 0}
            </div>
          </div>
        </div>

        {/* Checklist */}
        <div className="space-y-3 pt-2">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Recon Stages
          </div>
          <div className="space-y-2.5">
            {steps.map((s) => {
              const isDone = currentStep > s.num;
              const isCurrent = currentStep === s.num;

              return (
                <div
                  key={s.num}
                  className={`flex items-center space-x-3 p-2.5 rounded-xl transition-all ${
                    isCurrent
                      ? 'bg-indigo-500/10 border border-indigo-500/30 text-white'
                      : isDone
                      ? 'text-slate-300'
                      : 'text-slate-500 opacity-60'
                  }`}
                >
                  <div className="shrink-0">
                    {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                    {isCurrent && <Loader2 className="w-4 h-4 text-indigo-400 animate-spin" />}
                    {!isDone && !isCurrent && <Circle className="w-4 h-4 text-slate-600" />}
                  </div>

                  <span className="text-xs sm:text-sm font-medium">
                    {s.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Toggle Detailed Terminal Output */}
        <div className="pt-2 border-t border-[#222736]">
          <button
            onClick={() => setShowLogs(!showLogs)}
            className="w-full py-2 px-3 rounded-xl bg-[#0e1017] hover:bg-[#12151e] text-xs font-medium text-slate-300 hover:text-white flex items-center justify-between transition-colors"
          >
            <div className="flex items-center space-x-2">
              <Terminal className="w-3.5 h-3.5 text-indigo-400" />
              <span>{showLogs ? 'Hide live terminal logs' : 'View live terminal logs'}</span>
            </div>
            {showLogs ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {showLogs && (
            <div className="mt-3">
              <TerminalLog logs={scan.logs || []} isScanning={true} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
