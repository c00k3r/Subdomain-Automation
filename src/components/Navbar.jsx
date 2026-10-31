import React from 'react';
import { Shield, History, PlusCircle } from 'lucide-react';

export const Navbar = ({ currentView, onViewChange, onNewScan, hasActiveScan }) => {
  return (
    <header className="border-b border-[#232733] bg-[#11131a]/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand */}
        <div 
          onClick={onNewScan}
          className="flex items-center space-x-2.5 cursor-pointer group"
        >
          <div className="w-9 h-9 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 group-hover:bg-indigo-500/20 transition-all">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="font-bold text-base text-white tracking-tight flex items-center space-x-2">
              <span>ReconForge</span>
              <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                v2.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
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
