import React from 'react';
import { Shield, Radio, Terminal, Download, Cpu } from 'lucide-react';

export const Navbar = ({ isScanning = false, activeScan = null }) => {
  return (
    <header className="border-b border-[#181b24] bg-[#090b10]/95 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-[1520px] mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-6">
        {/* Brand Zone */}
        <div className="flex items-center space-x-3 shrink-0">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.15)]">
            <Shield className="w-4 h-4" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="font-mono font-bold text-sm text-slate-100 tracking-wider">
              RECON<span className="text-emerald-400">FORGE</span>
            </span>
            <span className="text-[10px] font-mono text-slate-500">
              v2.0 // VAPT AUTOMATION
            </span>
          </div>
        </div>

        {/* Center Telemetry & Quick Scope */}
        <div className="hidden lg:flex items-center space-x-6 font-mono text-xs text-slate-400">
          <div className="flex items-center space-x-2">
            <span className="text-slate-500">MODULES:</span>
            <span className="text-slate-300">crt.sh</span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-300">OTX</span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-300">DoH</span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-300">Httpx</span>
          </div>

          {activeScan && (
            <div className="flex items-center space-x-3 pl-4 border-l border-slate-800">
              <span className="text-slate-500">TARGET:</span>
              <span className="text-emerald-400 font-semibold">{activeScan.domain}</span>
              <span className="text-slate-600">·</span>
              <span className="text-slate-300">{activeScan.totalSubdomains} assets</span>
              <span className="text-slate-600">·</span>
              <span className="text-emerald-400">{activeScan.aliveCount} alive</span>
            </div>
          )}
        </div>

        {/* Right Status Indicator */}
        <div className="flex items-center space-x-3 shrink-0 font-mono text-xs">
          <div className={`px-2.5 py-1 rounded-md border flex items-center space-x-2 ${
            isScanning
              ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
              : 'bg-slate-900/60 border-slate-800 text-slate-400'
          }`}>
            <span className={`w-2 h-2 rounded-full ${
              isScanning ? 'bg-emerald-400 animate-radar' : 'bg-slate-500'
            }`} />
            <span className="text-[11px] font-medium tracking-wide">
              {isScanning ? 'RECON IN PROGRESS' : 'STANDBY'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
