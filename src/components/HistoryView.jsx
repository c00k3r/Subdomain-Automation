import React from 'react';
import { History, Globe, Clock, ArrowLeft, ArrowRight, ShieldCheck } from 'lucide-react';

export const HistoryView = ({ scans = [], onSelectScan, onBack }) => {
  return (
    <div className="max-w-3xl mx-auto py-8 px-4 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center space-x-1.5 text-xs font-semibold text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Scanner</span>
        </button>

        <span className="text-xs text-slate-500 font-mono">
          {scans.length} past scans recorded
        </span>
      </div>

      <div className="space-y-2">
        <h2 className="text-2xl font-bold text-white tracking-tight">
          Scan History
        </h2>
        <p className="text-sm text-slate-400">
          Review previously completed reconnaissance scans and export their reports.
        </p>
      </div>

      <div className="space-y-3">
        {scans.length === 0 ? (
          <div className="p-12 text-center text-slate-500 bg-[#161822] border border-[#262b3b] rounded-2xl text-sm">
            No previous scans found. Start a new scan from the homepage.
          </div>
        ) : (
          scans.map((scan) => (
            <div
              key={scan.id}
              onClick={() => onSelectScan(scan.id)}
              className="p-4 rounded-xl bg-[#161822] border border-[#262b3b] hover:border-indigo-500/50 hover:bg-[#1a1d29] transition-all cursor-pointer flex items-center justify-between group"
            >
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <Globe className="w-4 h-4 text-indigo-400" />
                  <span className="font-mono text-base font-bold text-white group-hover:text-indigo-300 transition-colors">
                    {scan.domain}
                  </span>
                </div>

                <div className="flex items-center space-x-3 text-xs text-slate-400">
                  <span>
                    <strong className="text-slate-200">{scan.totalSubdomains}</strong> subdomains
                  </span>
                  <span>·</span>
                  <span>
                    <strong className="text-emerald-400">{scan.aliveCount}</strong> live hosts
                  </span>
                  {scan.executionTime && (
                    <>
                      <span>·</span>
                      <span className="flex items-center space-x-1">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{scan.executionTime}s</span>
                      </span>
                    </>
                  )}
                </div>
              </div>

              <div className="flex items-center space-x-2 text-xs font-semibold text-indigo-400 group-hover:translate-x-1 transition-transform">
                <span>View Results</span>
                <ArrowRight className="w-4 h-4" />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
