import React, { useState, useEffect } from 'react';
import { Loader2, CheckCircle2, Circle, Terminal, ChevronDown, ChevronUp, ArrowRight, ShieldCheck } from 'lucide-react';
import { TerminalLog } from './TerminalLog';

const steps = [
  { num: 1, label: 'Validating scope, DNS resolvers & wildcard detection' },
  { num: 2, label: 'Querying Certificate Transparency logs (crt.sh API)' },
  { num: 3, label: 'Querying Passive Threat Feeds (AlienVault OTX & HackerTarget)' },
  { num: 4, label: 'Merging unique hosts & normalizing FQDNs' },
  { num: 5, label: 'Active HTTP/HTTPS service probing & SSRF safeguards' },
  { num: 6, label: 'Compiling security audit reports & markdown artifacts' },
];

export const ScanProgress = ({ scan, onComplete }) => {
  const [showLogs, setShowLogs] = useState(false);

  // Auto-redirect as soon as scan status is completed
  useEffect(() => {
    if (scan?.status === 'completed') {
      const timer = setTimeout(() => {
        onComplete?.();
      }, 700);
      return () => clearTimeout(timer);
    }
  }, [scan?.status, onComplete]);

  if (!scan) return null;

  const isCompleted = scan.status === 'completed';
  const currentStep = isCompleted ? 6 : (scan.step || 1);
  const progressPercent = isCompleted ? 100 : Math.min(100, Math.round((currentStep / 6) * 100));

  return (
    <div className="max-w-3xl mx-auto py-10 px-4 space-y-6 animate-fade-in">
      {/* Header status */}
      <div className="text-center space-y-2">
        {isCompleted ? (
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-emerald-500/15 text-emerald-400 text-xs font-semibold border border-emerald-500/25">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Reconnaissance Complete</span>
          </div>
        ) : (
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-500/10 text-indigo-400 text-xs font-medium">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            <span>Reconnaissance in progress</span>
          </div>
        )}
        
        <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight flex items-center justify-center space-x-2">
          <span>{isCompleted ? 'Scan Finished for' : 'Scanning'}</span>
          <span className="text-indigo-400 font-mono">{scan.domain}</span>
        </h2>
        
        <p className="text-slate-400 text-sm">
          {isCompleted
            ? 'Summary & markdown reports compiled successfully. Redirecting to results...'
            : 'Please wait while we gather subdomains and probe active servers...'}
        </p>
      </div>

      {/* Clean Progress Card */}
      <div className="bg-[#161822] border border-[#262b3b] rounded-2xl p-6 shadow-xl space-y-6">
        {/* Progress Bar */}
        <div className="space-y-2">
          <div className="flex justify-between text-xs font-medium text-slate-400">
            <span>Progress</span>
            <span className={isCompleted ? 'text-emerald-400 font-bold' : 'text-indigo-400 font-bold'}>
              {progressPercent}%
            </span>
          </div>
          <div className="h-2.5 w-full bg-[#0e1017] rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ease-out ${
                isCompleted ? 'bg-emerald-500' : 'bg-indigo-500'
              }`}
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>

        {/* Live Counters */}
        <div className="grid grid-cols-3 gap-2 sm:gap-4 pt-2 border-t border-[#222736]">
          <div className="p-3 sm:p-4 rounded-xl bg-[#0e1017] border border-[#202533] text-center">
            <span className="text-[11px] sm:text-xs text-slate-400 font-medium">Subdomains</span>
            <div className="text-xl sm:text-2xl font-bold text-white font-mono mt-1">
              {scan.totalSubdomains || scan.subdomains?.length || 0}
            </div>
          </div>

          <div className="p-3 sm:p-4 rounded-xl bg-[#0e1017] border border-[#202533] text-center">
            <span className="text-[11px] sm:text-xs text-emerald-400/90 font-medium">HTTP Live</span>
            <div className="text-xl sm:text-2xl font-bold text-emerald-400 font-mono mt-1">
              {scan.httpCount !== undefined ? scan.httpCount : (scan.aliveCount || 0)}
            </div>
          </div>

          <div className="p-3 sm:p-4 rounded-xl bg-[#0e1017] border border-[#202533] text-center">
            <span className="text-[11px] sm:text-xs text-sky-400/90 font-medium">DNS Only</span>
            <div className="text-xl sm:text-2xl font-bold text-sky-400 font-mono mt-1">
              {scan.dnsCount !== undefined ? scan.dnsCount : 0}
            </div>
          </div>
        </div>

        {/* Manual Redirect Button if scan completed */}
        {isCompleted && (
          <button
            onClick={() => onComplete?.()}
            className="w-full py-3 px-4 rounded-xl font-semibold text-white bg-indigo-600 hover:bg-indigo-500 active:scale-[0.99] transition-all flex items-center justify-center space-x-2 shadow-lg shadow-indigo-600/30 text-sm"
          >
            <span>View Results & Reports</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        )}

        {/* Checklist */}
        <div className="space-y-3 pt-2">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Recon Stages
          </div>
          <div className="space-y-2.5">
            {steps.map((s) => {
              const isDone = currentStep > s.num || (s.num === 6 && isCompleted);
              const isCurrent = currentStep === s.num && !isCompleted;

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
              <TerminalLog logs={scan.logs || []} isScanning={!isCompleted} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
