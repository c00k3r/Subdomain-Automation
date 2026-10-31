import React from 'react';
import { History, PlusCircle } from 'lucide-react';

// Custom ReconForge brandmark: Tactical cyber shield with radar reticle and forged core
export const ReconForgeLogo = ({ className = "w-6 h-6" }) => (
  <svg
    viewBox="0 0 28 28"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={className}
  >
    <defs>
      <linearGradient id="rf-grad" x1="2" y1="2" x2="26" y2="26" gradientUnits="userSpaceOnUse">
        <stop stopColor="#6366f1" />
        <stop offset="0.5" stopColor="#818cf8" />
        <stop offset="1" stopColor="#c084fc" />
      </linearGradient>
    </defs>
    {/* Outer Faceted Recon Shield */}
    <path
      d="M14 2.5L24 6.5V13.8C24 19.6 19.8 24.3 14 26C8.2 24.3 4 19.6 4 13.8V6.5L14 2.5Z"
      stroke="url(#rf-grad)"
      strokeWidth="1.75"
      strokeLinejoin="round"
    />
    {/* Concentric Radar Reticle Ring */}
    <circle cx="14" cy="14" r="6.2" stroke="#818cf8" strokeWidth="1.2" strokeDasharray="2.5 2" opacity="0.8" />
    
    {/* Reticle Target Crosshairs */}
    <path d="M14 4.8V8M14 20V23.2M4.8 14H8M20 14H23.2" stroke="#c7d2fe" strokeWidth="1.5" strokeLinecap="round" />
    
    {/* Forged Core Pulse */}
    <circle cx="14" cy="14" r="2.8" fill="url(#rf-grad)" />
    <circle cx="14" cy="14" r="1.1" fill="#ffffff" />
  </svg>
);

export const Navbar = ({ currentView, onViewChange, onNewScan, hasActiveScan }) => {
  return (
    <header className="border-b border-[#232733] bg-[#11131a]/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand */}
        <div 
          onClick={onNewScan}
          className="flex items-center space-x-3 cursor-pointer group"
        >
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500/15 to-purple-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400 group-hover:border-indigo-400/50 group-hover:shadow-[0_0_16px_rgba(99,102,241,0.25)] transition-all">
            <ReconForgeLogo className="w-6 h-6" />
          </div>
          <div>
            <div className="font-bold text-base text-white tracking-tight flex items-center space-x-2">
              <span className="bg-gradient-to-r from-white via-slate-100 to-slate-300 bg-clip-text text-transparent">ReconForge</span>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded-md bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 font-mono tracking-tight shadow-sm">
                v2.1
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block tracking-normal">
              Subdomain Discovery & Live Host Detection
            </p>
          </div>
        </div>

        {/* Navigation & Actions */}
        <div className="flex items-center space-x-2 sm:space-x-4">
          <button
            onClick={() => onViewChange('history')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center space-x-1.5 transition-colors ${
              currentView === 'history'
                ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <History className="w-4 h-4" />
            <span>Past Scans</span>
          </button>

          {currentView !== 'scan' && (
            <button
              onClick={onNewScan}
              className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 transition-all shadow-md shadow-indigo-600/20 flex items-center space-x-1.5"
            >
              <PlusCircle className="w-4 h-4" />
              <span>New Scan</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
