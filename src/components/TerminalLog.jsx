import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Copy, Check, Play, Pause, Search } from 'lucide-react';

export const TerminalLog = ({ logs = [], isScanning = false }) => {
  const containerRef = useRef(null);
  const [copied, setCopied] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filterText, setFilterText] = useState('');

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const copyLogs = () => {
    const rawText = logs
      .map((l) => l.replace(/\x1b\[[0-9;]*m/g, ''))
      .join('\n');
    navigator.clipboard.writeText(rawText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const renderColoredText = (text) => {
    const regex = /\x1b\[([0-9;]+)m/g;
    const parts = [];
    let lastIndex = 0;
    let currentColor = '';

    let match;
    while ((match = regex.exec(text)) !== null) {
      const plainSegment = text.substring(lastIndex, match.index);
      if (plainSegment) {
        parts.push({ text: plainSegment, colorClass: currentColor });
      }

      const code = match[1];
      if (code === '0') {
        currentColor = '';
      } else if (code === '32' || code === '0;32') {
        currentColor = 'text-emerald-400 font-semibold';
      } else if (code === '31' || code === '0;31') {
        currentColor = 'text-rose-400 font-semibold';
      } else if (code === '34' || code === '0;34') {
        currentColor = 'text-sky-400 font-bold';
      } else if (code === '36' || code === '0;36') {
        currentColor = 'text-teal-300';
      } else if (code === '1;33' || code === '33') {
        currentColor = 'text-amber-400 font-semibold';
      }

      lastIndex = regex.lastIndex;
    }

    const remaining = text.substring(lastIndex);
    if (remaining) {
      parts.push({ text: remaining, colorClass: currentColor });
    }

    return (
      <>
        {parts.map((p, idx) => (
          <span key={idx} className={p.colorClass || 'text-slate-300'}>
            {p.text}
          </span>
        ))}
      </>
    );
  };

  const filteredLogs = logs.filter((log) => {
    if (!filterText) return true;
    const clean = log.replace(/\x1b\[[0-9;]*m/g, '').toLowerCase();
    return clean.includes(filterText.toLowerCase());
  });

  return (
    <div className="rounded-xl border border-[#1a1f2c] bg-[#07090e] shadow-2xl overflow-hidden flex flex-col h-full min-h-[460px]">
      {/* Shell Title Bar */}
      <div className="flex items-center justify-between px-3.5 py-2.5 bg-[#0b0e15] border-b border-[#181c26]">
        <div className="flex items-center space-x-2">
          <div className="flex space-x-1.5 mr-1">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
          </div>
          <span className="text-xs font-mono text-slate-300 font-semibold tracking-wide flex items-center space-x-1.5">
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            <span>recon@engine:~#</span>
          </span>
          {isScanning && (
            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 animate-pulse">
              STREAMING
            </span>
          )}
        </div>

        <div className="flex items-center space-x-2">
          {/* Filter input inside terminal */}
          <div className="relative hidden sm:block">
            <Search className="w-3 h-3 text-slate-500 absolute left-2 top-2" />
            <input
              type="text"
              placeholder="Grep logs..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              className="text-[11px] font-mono bg-[#07090e] border border-slate-800 rounded pl-6 pr-2 py-1 text-slate-300 placeholder-slate-600 focus:outline-none focus:border-emerald-500 w-28 focus:w-36 transition-all"
            />
          </div>

          {/* Auto-scroll toggle */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1 rounded text-[10px] font-mono flex items-center space-x-1 border transition-colors ${
              autoScroll
                ? 'bg-emerald-950/40 border-emerald-800/50 text-emerald-400'
                : 'bg-slate-900 border-slate-800 text-slate-400'
            }`}
            title={autoScroll ? 'Auto-scroll enabled' : 'Auto-scroll paused'}
          >
            {autoScroll ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
          </button>

          {/* Copy button */}
          <button
            onClick={copyLogs}
            className="flex items-center space-x-1 text-[11px] font-mono text-slate-400 hover:text-slate-200 transition-colors px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800"
            title="Copy raw terminal output"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400 text-[10px]">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span className="text-[10px]">Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Terminal Viewport */}
      <div
        ref={containerRef}
        className="p-3.5 overflow-y-auto flex-1 font-mono text-xs leading-relaxed space-y-1 select-text relative scanline scroll-smooth"
      >
        {filteredLogs.length === 0 ? (
          <div className="text-slate-600 italic py-6 text-center">
            {logs.length === 0
              ? '// Awaiting target input to initialize recon pipeline...'
              : '// No log entries match your filter.'}
          </div>
        ) : (
          filteredLogs.map((log, index) => (
            <div key={index} className="whitespace-pre-wrap break-all tracking-wide">
              {renderColoredText(log)}
            </div>
          ))
        )}
        {isScanning && (
          <div className="flex items-center space-x-2 text-emerald-400 pt-1 text-xs">
            <span className="inline-block animate-pulse font-bold">&gt;&gt;</span>
            <span className="text-slate-400 text-[11px]">Probing targets concurrently...</span>
          </div>
        )}
      </div>
    </div>
  );
};
