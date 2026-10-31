import React, { useEffect, useRef } from 'react';
import { Terminal, Copy, Check } from 'lucide-react';

interface Props {
  logs: string[];
  isScanning: boolean;
}

export const TerminalLog: React.FC<Props> = ({ logs, isScanning }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = React.useState(false);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  const copyLogs = () => {
    const rawText = logs
      .map((l) => l.replace(/\x1b\[[0-9;]*m/g, ''))
      .join('\n');
    navigator.clipboard.writeText(rawText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const renderColoredText = (text: string) => {
    // Basic ANSI color parser
    const regex = /\x1b\[([0-9;]+)m/g;
    const parts: { text: string; colorClass?: string }[] = [];
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
        currentColor = 'text-blue-400 font-bold';
      } else if (code === '36' || code === '0;36') {
        currentColor = 'text-cyan-300';
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

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/90 shadow-2xl overflow-hidden flex flex-col h-[380px]">
      <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <div className="flex space-x-1.5 mr-2">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
          </div>
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-mono text-slate-300 font-medium tracking-wide">
            terminal://recon.sh
          </span>
          {isScanning && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/20 text-blue-400 animate-pulse">
              RUNNING
            </span>
          )}
        </div>

        <button
          onClick={copyLogs}
          className="flex items-center space-x-1 text-xs text-slate-400 hover:text-slate-200 transition-colors px-2 py-1 rounded bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60"
          title="Copy raw log output"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400 text-xs">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      <div
        ref={containerRef}
        className="p-4 overflow-y-auto flex-1 font-mono text-xs leading-relaxed space-y-1 select-text scroll-smooth"
      >
        {logs.length === 0 ? (
          <div className="text-slate-600 italic">No execution logs yet. Enter a target domain to start recon.</div>
        ) : (
          logs.map((log, index) => (
            <div key={index} className="whitespace-pre-wrap break-all">
              {renderColoredText(log)}
            </div>
          ))
        )}
        {isScanning && (
          <div className="flex items-center space-x-2 text-emerald-400 pt-1">
            <span className="animate-spin inline-block">⠋</span>
            <span className="text-slate-400 text-xs">Executing step in background...</span>
          </div>
        )}
      </div>
    </div>
  );
};
