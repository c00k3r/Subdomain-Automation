import React from 'react';
import { ShieldCheck, Search, Globe, Filter, Activity, FileCheck, Check, Loader2 } from 'lucide-react';

const pipelineStages = [
  {
    num: 1,
    id: 'deps',
    label: 'Scope & Resolvers',
    desc: 'Target validation',
    icon: ShieldCheck,
  },
  {
    num: 2,
    id: 'crtsh',
    label: 'Cert Transparency',
    desc: 'crt.sh Log Mining',
    icon: Search,
  },
  {
    num: 3,
    id: 'asset',
    label: 'Passive Feeds',
    desc: 'OTX & HackerTarget',
    icon: Globe,
  },
  {
    num: 4,
    id: 'merge',
    label: 'Deduplicate',
    desc: 'FQDN Normalization',
    icon: Filter,
  },
  {
    num: 5,
    id: 'httpx',
    label: 'Live Probing',
    desc: 'HTTP/TLS & SSRF check',
    icon: Activity,
  },
  {
    num: 6,
    id: 'report',
    label: 'Audit Reports',
    desc: 'Artifacts & Metrics',
    icon: FileCheck,
  },
];

export const ScanWorkflow = ({
  step = 0,
  isScanning = false,
  totalSubdomains = 0,
  aliveCount = 0,
}) => {
  return (
    <div className="w-full bg-[#0d0f15] border border-[#1c202c] rounded-xl p-3 sm:p-4 shadow-xl">
      <div className="flex items-center justify-between mb-3 text-xs font-mono text-slate-400">
        <div className="flex items-center space-x-2">
          <span className="text-emerald-400 font-bold">//</span>
          <span className="text-slate-200 font-semibold uppercase tracking-wider text-[11px]">
            Execution Pipeline
          </span>
        </div>
        <div className="text-[11px] text-slate-500">
          Step {Math.min(step, 6)} of 6
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-2 relative">
        {pipelineStages.map((stage, idx) => {
          const Icon = stage.icon;
          const isDone = step > stage.num || (step === 6 && !isScanning);
          const isCurrent = step === stage.num && isScanning;
          const isPending = step < stage.num;

          return (
            <div
              key={stage.id}
              className={`relative rounded-lg p-2.5 transition-all duration-200 border flex flex-col justify-between ${
                isCurrent
                  ? 'bg-emerald-950/25 border-emerald-500/60 shadow-[0_0_15px_rgba(16,185,129,0.12)]'
                  : isDone
                  ? 'bg-[#11141d] border-emerald-900/40 text-slate-300'
                  : 'bg-[#090b10] border-slate-900 text-slate-600 opacity-60'
              }`}
            >
              {/* Top row in node */}
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center space-x-1.5">
                  <div
                    className={`w-6 h-6 rounded flex items-center justify-center text-xs font-mono font-bold ${
                      isCurrent
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : isDone
                        ? 'bg-emerald-900/30 text-emerald-300'
                        : 'bg-slate-800 text-slate-500'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[10px] font-mono font-semibold text-slate-400">
                    0{stage.num}
                  </span>
                </div>

                <div>
                  {isCurrent && (
                    <Loader2 className="w-3.5 h-3.5 text-emerald-400 animate-spin" />
                  )}
                  {isDone && (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  )}
                </div>
              </div>

              {/* Title & Desc */}
              <div>
                <div className={`text-xs font-medium tracking-tight truncate ${
                  isCurrent ? 'text-emerald-300 font-semibold' : isDone ? 'text-slate-200' : 'text-slate-500'
                }`}>
                  {stage.label}
                </div>
                <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5">
                  {stage.desc}
                </div>
              </div>

              {/* Output Tag */}
              <div className="mt-2 min-h-[16px] text-[10px] font-mono">
                {stage.num === 4 && totalSubdomains > 0 && isDone && (
                  <span className="text-cyan-400 font-semibold">
                    {totalSubdomains} targets
                  </span>
                )}
                {stage.num === 5 && aliveCount > 0 && isDone && (
                  <span className="text-emerald-400 font-semibold">
                    {aliveCount} alive
                  </span>
                )}
                {isCurrent && (
                  <span className="text-emerald-400 animate-pulse">
                    Probing...
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
