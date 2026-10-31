import React from 'react';
import { CheckCircle2, CircleDashed, Loader2, Search, Filter, ShieldCheck, FileText, Globe } from 'lucide-react';

const stepsConfig = [
  {
    num: 1,
    title: 'Check Dependencies',
    desc: 'Verify DNS resolvers & network engine',
    icon: ShieldCheck,
  },
  {
    num: 2,
    title: 'Subfinder',
    desc: 'Certificate Transparency (crt.sh)',
    icon: Search,
  },
  {
    num: 3,
    title: 'Assetfinder',
    desc: 'AlienVault OTX & passive DNS feeds',
    icon: Globe,
  },
  {
    num: 4,
    title: 'Merge & Deduplicate',
    desc: 'Normalize and sort unique targets',
    icon: Filter,
  },
  {
    num: 5,
    title: 'Live Hosts (Httpx)',
    desc: 'Probe HTTP/HTTPS, SSL & status codes',
    icon: Globe,
  },
  {
    num: 6,
    title: 'Generate Reports',
    desc: 'Output summary, markdown & recon logs',
    icon: FileText,
  },
];

export const ScanWorkflow = ({
  step = 0,
  isScanning = false,
  totalSubdomains = 0,
  aliveCount = 0,
}) => {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {stepsConfig.map((s) => {
        const Icon = s.icon;
        const isDone = step > s.num || (step === 6 && !isScanning);
        const isCurrent = step === s.num && isScanning;
        const isPending = step < s.num;

        return (
          <div
            key={s.num}
            className={`relative p-3.5 rounded-xl border transition-all duration-300 ${
              isCurrent
                ? 'bg-blue-950/40 border-blue-500/80 shadow-[0_0_15px_rgba(59,130,246,0.25)]'
                : isDone
                ? 'bg-slate-900/60 border-emerald-500/30'
                : 'bg-slate-900/30 border-slate-800/80 opacity-60'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div
                className={`p-1.5 rounded-lg ${
                  isCurrent
                    ? 'bg-blue-500/20 text-blue-400'
                    : isDone
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : 'bg-slate-800 text-slate-500'
                }`}
              >
                <Icon className="w-4 h-4" />
              </div>
              <div>
                {isCurrent && (
                  <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
                )}
                {isDone && (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
                {isPending && (
                  <CircleDashed className="w-4 h-4 text-slate-600" />
                )}
              </div>
            </div>

            <div className="text-xs font-mono font-semibold text-slate-200">
              [{s.num}/6] {s.title}
            </div>
            <div className="text-[11px] text-slate-400 mt-1 leading-tight line-clamp-2">
              {s.desc}
            </div>

            {s.num === 4 && totalSubdomains > 0 && isDone && (
              <div className="mt-2 text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800/50 inline-block">
                {totalSubdomains} unique
              </div>
            )}

            {s.num === 5 && aliveCount > 0 && isDone && (
              <div className="mt-2 text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800/50 inline-block">
                {aliveCount} alive
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
