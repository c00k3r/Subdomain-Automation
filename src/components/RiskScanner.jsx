import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Key, Server, Cpu, ExternalLink, Copy, Check, ArrowRight, ShieldCheck } from 'lucide-react';

export const RiskScanner = ({ scan }) => {
  const [activeTab, setActiveTab] = useState('takeover'); // 'takeover' | 'auth' | 'api' | 'staging'
  const [copiedKey, setCopiedKey] = useState(null);

  if (!scan) return null;

  const aliveHosts = scan.aliveHosts || [];
  const allSubdomains = scan.subdomains || [];

  // Group assets into VAPT categories
  const authTargets = aliveHosts.filter((h) => h.category === 'auth' || /(?:auth|login|sso|vpn|portal|identity)/i.test(h.subdomain));
  const apiTargets = aliveHosts.filter((h) => h.category === 'api' || /(?:api|graphql|gateway|v[0-9])/i.test(h.subdomain));
  const stagingTargets = aliveHosts.filter((h) => h.category === 'staging' || /(?:dev|staging|stage|test|internal|corp)/i.test(h.subdomain));

  // Identify potential takeovers
  const takeoverTargets = aliveHosts.filter((h) => h.takeoverRisk && h.takeoverRisk.isVulnerable);

  // If no live host returned explicit takeover, let's also scan all 404s or dangling CNAME candidates
  const fallbackTakeovers = aliveHosts.filter((h) => h.statusCode === 404 || h.statusCode === 0);

  const handleCopy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Category Navigation Pills */}
      <div className="bg-[#161822] border border-[#262b3b] rounded-2xl p-2 flex flex-wrap gap-1.5 font-mono text-xs">
        <button
          onClick={() => setActiveTab('takeover')}
          className={`px-3 py-2 rounded-xl flex items-center space-x-2 transition-all ${
            activeTab === 'takeover'
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold shadow-sm'
              : 'text-slate-400 hover:text-white hover:bg-[#0e1017]'
          }`}
        >
          <ShieldAlert className="w-4 h-4 text-amber-400" />
          <span>Subdomain Takeover ({takeoverTargets.length || fallbackTakeovers.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('auth')}
          className={`px-3 py-2 rounded-xl flex items-center space-x-2 transition-all ${
            activeTab === 'auth'
              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-semibold shadow-sm'
              : 'text-slate-400 hover:text-white hover:bg-[#0e1017]'
          }`}
        >
          <Key className="w-4 h-4 text-rose-400" />
          <span>Auth & VPN ({authTargets.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('api')}
          className={`px-3 py-2 rounded-xl flex items-center space-x-2 transition-all ${
            activeTab === 'api'
              ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 font-semibold shadow-sm'
              : 'text-slate-400 hover:text-white hover:bg-[#0e1017]'
          }`}
        >
          <Cpu className="w-4 h-4 text-sky-400" />
          <span>API Endpoints ({apiTargets.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('staging')}
          className={`px-3 py-2 rounded-xl flex items-center space-x-2 transition-all ${
            activeTab === 'staging'
              ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 font-semibold shadow-sm'
              : 'text-slate-400 hover:text-white hover:bg-[#0e1017]'
          }`}
        >
          <Server className="w-4 h-4 text-purple-400" />
          <span>Internal & Staging ({stagingTargets.length})</span>
        </button>
      </div>

      {/* TAB 1: Takeover Findings */}
      {activeTab === 'takeover' && (
        <div className="space-y-3">
          {takeoverTargets.length > 0 ? (
            takeoverTargets.map((target, idx) => (
              <div
                key={idx}
                className="p-5 rounded-2xl bg-[#161822] border-2 border-amber-500/40 shadow-xl space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 text-rose-400 border border-rose-500/30">
                      {target.takeoverRisk.severity || 'CRITICAL'}
                    </span>
                    <span className="text-xs font-mono font-semibold text-amber-300 flex items-center space-x-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>Potential Subdomain Takeover Detected</span>
                    </span>
                  </div>

                  <span className="text-xs font-mono text-slate-400">
                    Service: <strong className="text-white">{target.takeoverRisk.service}</strong>
                  </span>
                </div>

                <div className="space-y-1">
                  <div className="text-base font-bold font-mono text-white flex items-center space-x-2">
                    <span>{target.subdomain}</span>
                    <span className="text-xs font-normal text-rose-400 font-mono">(HTTP {target.statusCode})</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {target.takeoverRisk.reason}
                  </p>
                </div>

                <div className="p-3 rounded-xl bg-[#0e1017] border border-[#232733] text-xs text-slate-400 space-y-1">
                  <strong className="text-slate-200">Remediation:</strong>
                  <p className="text-[11px] text-slate-400">{target.takeoverRisk.remediation}</p>
                </div>

                <div className="flex items-center justify-between pt-1 text-xs">
                  <button
                    onClick={() => handleCopy(`curl -I ${target.url}`, `takeover_${idx}`)}
                    className="px-3 py-1.5 rounded-lg bg-[#0e1017] hover:bg-slate-800 text-slate-300 border border-[#262b3b] font-mono text-xs flex items-center space-x-1.5"
                  >
                    {copiedKey === `takeover_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === `takeover_${idx}` ? 'curl PoC Copied' : 'Copy curl PoC'}</span>
                  </button>

                  <a
                    href={target.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3.5 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold flex items-center space-x-1"
                  >
                    <span>Verify Live</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              </div>
            ))
          ) : fallbackTakeovers.length > 0 ? (
            <div className="p-6 rounded-2xl bg-[#161822] border border-[#262b3b] space-y-4">
              <div className="flex items-center space-x-2 text-xs font-semibold text-emerald-400">
                <ShieldCheck className="w-4 h-4" />
                <span>Zero Known Dangling Cloud Signatures Found</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                No active subdomains matched high-risk signatures (AWS S3, GitHub Pages, Heroku 404s).
                The following {fallbackTakeovers.length} hosts returned non-200 status codes for manual auditing:
              </p>
              <div className="space-y-2">
                {fallbackTakeovers.slice(0, 5).map((h, i) => (
                  <div key={i} className="p-2.5 rounded-xl bg-[#0e1017] border border-[#232733] flex items-center justify-between text-xs font-mono">
                    <span className="text-white">{h.subdomain}</span>
                    <span className="text-amber-400 font-bold">Status: {h.statusCode || 'DNS only'}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-10 text-center text-slate-500 bg-[#161822] border border-[#262b3b] rounded-2xl text-xs font-mono">
              // All audited live hosts returned healthy 2xx/3xx response codes.
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Auth & VPN High-Value Targets */}
      {activeTab === 'auth' && (
        <div className="space-y-3">
          {authTargets.length === 0 ? (
            <div className="p-10 text-center text-slate-500 bg-[#161822] border border-[#262b3b] rounded-2xl text-xs font-mono">
              // No authentication or VPN subdomains identified in scope.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {authTargets.map((host, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-[#161822] border border-rose-500/20 hover:border-rose-500/40 transition-all space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/10 text-rose-400 border border-rose-500/20">
                      AUTH PERIMETER
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">{host.statusCode} OK · {host.latencyMs}ms</span>
                  </div>

                  <a href={host.url} target="_blank" rel="noopener noreferrer" className="font-mono text-sm font-semibold text-white hover:text-rose-300 flex items-center space-x-1 truncate">
                    <span className="truncate">{host.url}</span>
                    <ExternalLink className="w-3.5 h-3.5 shrink-0 opacity-60" />
                  </a>

                  {host.techStack && (
                    <div className="flex flex-wrap gap-1">
                      {host.techStack.map((t, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-[#0e1017] text-slate-300 text-[10px] font-mono border border-[#232733]">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: API Endpoints */}
      {activeTab === 'api' && (
        <div className="space-y-3">
          {apiTargets.length === 0 ? (
            <div className="p-10 text-center text-slate-500 bg-[#161822] border border-[#262b3b] rounded-2xl text-xs font-mono">
              // No API-specific subdomains identified in scope.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {apiTargets.map((host, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-[#161822] border border-sky-500/20 hover:border-sky-500/40 transition-all space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-sky-500/10 text-sky-400 border border-sky-500/20">
                      API GATEWAY
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">{host.statusCode} OK · {host.latencyMs}ms</span>
                  </div>

                  <a href={host.url} target="_blank" rel="noopener noreferrer" className="font-mono text-sm font-semibold text-white hover:text-sky-300 flex items-center space-x-1 truncate">
                    <span className="truncate">{host.url}</span>
                    <ExternalLink className="w-3.5 h-3.5 shrink-0 opacity-60" />
                  </a>

                  {host.techStack && (
                    <div className="flex flex-wrap gap-1">
                      {host.techStack.map((t, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-[#0e1017] text-slate-300 text-[10px] font-mono border border-[#232733]">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: Internal & Staging */}
      {activeTab === 'staging' && (
        <div className="space-y-3">
          {stagingTargets.length === 0 ? (
            <div className="p-10 text-center text-slate-500 bg-[#161822] border border-[#262b3b] rounded-2xl text-xs font-mono">
              // No internal or staging subdomains identified in scope.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {stagingTargets.map((host, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-[#161822] border border-purple-500/20 hover:border-purple-500/40 transition-all space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20">
                      INTERNAL / STAGING
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">{host.statusCode} OK · {host.latencyMs}ms</span>
                  </div>

                  <a href={host.url} target="_blank" rel="noopener noreferrer" className="font-mono text-sm font-semibold text-white hover:text-purple-300 flex items-center space-x-1 truncate">
                    <span className="truncate">{host.url}</span>
                    <ExternalLink className="w-3.5 h-3.5 shrink-0 opacity-60" />
                  </a>

                  {host.techStack && (
                    <div className="flex flex-wrap gap-1">
                      {host.techStack.map((t, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-[#0e1017] text-slate-300 text-[10px] font-mono border border-[#232733]">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
