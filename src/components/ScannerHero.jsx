import React, { useState } from 'react';
import { Search, Globe, Shield, ArrowRight, Zap, CheckCircle } from 'lucide-react';

export const ScannerHero = ({ onStartScan, isScanning, errorMessage }) => {
  const [domain, setDomain] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (domain.trim()) {
      onStartScan(domain.trim());
    }
  };

  const presets = [
    { name: 'HackerOne', domain: 'hackerone.com' },
    { name: 'OWASP', domain: 'owasp.org' },
    { name: 'Mozilla', domain: 'mozilla.org' },
    { name: 'GitHub', domain: 'github.com' },
  ];

  return (
    <div className="max-w-3xl mx-auto py-12 px-4 space-y-8 animate-fade-in">
      {/* Title & Description */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-medium">
          <Zap className="w-3.5 h-3.5" />
          <span>Automated Passive Reconnaissance</span>
        </div>
        
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Find all subdomains & live websites
        </h1>
        
        <p className="text-slate-400 text-sm sm:text-base max-w-xl mx-auto leading-relaxed">
          Enter any target domain to discover hidden subdomains, verify live web servers, and generate structured penetration testing reports.
        </p>
      </div>

      {/* Main Clean Input Box */}
      <div className="bg-[#161822] border border-[#262b3b] rounded-2xl p-3 sm:p-4 shadow-2xl">
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-2.5">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500">
              <Globe className="w-5 h-5 text-indigo-400/80" />
            </div>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="Enter domain (e.g. hackerone.com)"
              disabled={isScanning}
              autoFocus
              className="w-full pl-12 pr-4 py-3.5 bg-[#0e1017] border border-[#232736] rounded-xl text-white placeholder-slate-500 text-base focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={isScanning || !domain.trim()}
            className="px-7 py-3.5 rounded-xl font-semibold text-white bg-indigo-600 hover:bg-indigo-500 active:scale-[0.98] transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-indigo-600/30 flex items-center justify-center space-x-2 text-base shrink-0"
          >
            <span>Start Scan</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Quick Suggestion Buttons */}
        <div className="mt-4 pt-3.5 border-t border-[#202533] flex flex-wrap items-center justify-between gap-2 text-xs">
          <span className="text-slate-400 font-medium">Try an authorized target:</span>
          <div className="flex flex-wrap gap-1.5">
            {presets.map((preset) => (
              <button
                key={preset.domain}
                type="button"
                onClick={() => {
                  setDomain(preset.domain);
                  onStartScan(preset.domain);
                }}
                className="px-2.5 py-1 rounded-lg bg-[#0e1017] hover:bg-indigo-500/20 hover:text-indigo-300 text-slate-300 border border-[#232736] transition-colors"
              >
                {preset.name}
              </button>
            ))}
          </div>
        </div>

        {errorMessage && (
          <div className="mt-3 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
            {errorMessage}
          </div>
        )}
      </div>

      {/* 3 Simple Feature Cards (Explains what happens in plain English) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-4">
        <div className="p-4 rounded-xl bg-[#141620] border border-[#202433] space-y-2">
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center">
            <Search className="w-4 h-4" />
          </div>
          <h3 className="font-semibold text-sm text-white">Passive Discovery</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Extracts certificates and DNS records using Subfinder and AlienVault OTX feeds.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-[#141620] border border-[#202433] space-y-2">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
            <Globe className="w-4 h-4" />
          </div>
          <h3 className="font-semibold text-sm text-white">Live Host Probing</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Tests each subdomain via HTTP/HTTPS to detect responding web applications and titles.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-[#141620] border border-[#202433] space-y-2">
          <div className="w-8 h-8 rounded-lg bg-amber-500/10 text-amber-400 flex items-center justify-center">
            <CheckCircle className="w-4 h-4" />
          </div>
          <h3 className="font-semibold text-sm text-white">Reports & Export</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Exports clean lists (`subdomains.txt`, `alive.txt`) and ready-to-share Markdown reports.
          </p>
        </div>
      </div>
    </div>
  );
};
