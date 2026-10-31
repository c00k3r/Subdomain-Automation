import React from 'react';
import { Shield, Terminal, BookOpen, Layers } from 'lucide-react';

export const Navbar: React.FC = () => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-blue-600/20 border border-blue-500/40 text-blue-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-mono font-bold text-base text-slate-100 tracking-tight">
                ReconForge
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                v2.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
              Passive Subdomain Recon Automation
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 font-mono text-xs">
          <div className="hidden md:flex items-center space-x-2 text-slate-400 bg-slate-900/90 px-3 py-1.5 rounded-lg border border-slate-800">
            <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block animate-pulse" />
            <span>Modules: Subfinder • Assetfinder • Httpx</span>
          </div>

          <div className="text-[11px] text-slate-400 border border-slate-800 bg-slate-900/60 px-2.5 py-1.5 rounded-lg flex items-center space-x-1.5">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>./recon.sh -d target.com</span>
          </div>
        </div>
      </div>
    </header>
  );
};
