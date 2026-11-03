import React, { useRef, useEffect, useState } from 'react';
import { ZoomIn, ZoomOut, RotateCcw, ExternalLink, Copy, Check, Shield, Layers, Activity } from 'lucide-react';

export const TopologyGraph = ({ scan }) => {
  const canvasRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterMode, setFilterMode] = useState('all'); // 'all' | 'live' | 'hvt'
  const [zoom, setZoom] = useState(1);
  const [copied, setCopied] = useState(false);

  const domain = scan?.domain || 'target.com';
  const subdomains = scan?.subdomains || [];
  const aliveHosts = scan?.aliveHosts || [];

  // Map subdomains to nodes
  const nodes = React.useMemo(() => {
    if (!subdomains.length) return [];

    const aliveMap = new Map();
    aliveHosts.forEach((h) => {
      aliveMap.set(h.subdomain.toLowerCase(), h);
    });

    // Root node
    const list = [
      {
        id: 'root',
        label: domain,
        type: 'root',
        isAlive: true,
        x: 0,
        y: 0,
        radius: 26,
        color: '#6366f1',
      },
    ];

    // Cluster hubs
    const clusters = [
      { id: 'c_api', label: 'API Services', angle: -Math.PI / 4, color: '#38bdf8' },
      { id: 'c_auth', label: 'Auth & Portals', angle: Math.PI / 4, color: '#f59e0b' },
      { id: 'c_stage', label: 'Internal / Dev', angle: (3 * Math.PI) / 4, color: '#ec4899' },
      { id: 'c_cloud', label: 'Cloud & CDN', angle: -(3 * Math.PI) / 4, color: '#a855f7' },
      { id: 'c_web', label: 'Web Apps', angle: 0, color: '#10b981' },
    ];

    const clusterDist = 170;
    clusters.forEach((c) => {
      list.push({
        id: c.id,
        label: c.label,
        type: 'cluster',
        x: Math.cos(c.angle) * clusterDist,
        y: Math.sin(c.angle) * clusterDist,
        radius: 18,
        color: c.color,
      });
    });

    // Distribute subdomains into clusters
    subdomains.forEach((sub, idx) => {
      if (sub === domain) return;
      const aliveInfo = aliveMap.get(sub.toLowerCase());
      const isHttpLive = aliveInfo ? (aliveInfo.hostType === 'http' || (aliveInfo.statusCode > 0 && !aliveInfo.ssrfBlocked)) : false;
      const isDnsOnly = aliveInfo ? (aliveInfo.hostType === 'dns' || (aliveInfo.statusCode === 0 && !aliveInfo.ssrfBlocked)) : false;
      const isBlocked = aliveInfo ? (aliveInfo.hostType === 'blocked' || aliveInfo.ssrfBlocked) : false;
      const isAlive = !!aliveInfo;

      let nodeColor = '#475569'; // offline
      if (isHttpLive) nodeColor = '#10b981'; // emerald green
      else if (isDnsOnly) nodeColor = '#38bdf8'; // sky blue
      else if (isBlocked) nodeColor = '#f43f5e'; // rose red

      const category = aliveInfo?.category || (
        sub.includes('api') ? 'api' :
        sub.includes('auth') || sub.includes('vpn') || sub.includes('login') ? 'auth' :
        sub.includes('dev') || sub.includes('stage') || sub.includes('test') ? 'staging' :
        sub.includes('cdn') || sub.includes('s3') ? 'cloud' : 'general'
      );

      let targetCluster = 'c_web';
      if (category === 'api') targetCluster = 'c_api';
      else if (category === 'auth') targetCluster = 'c_auth';
      else if (category === 'staging') targetCluster = 'c_stage';
      else if (category === 'cloud') targetCluster = 'c_cloud';

      const clusterObj = clusters.find((c) => c.id === targetCluster) || clusters[4];
      const clusterAngle = clusterObj.angle;

      // Spread nodes outward from their cluster hub
      const spreadAngle = clusterAngle + ((idx % 8) - 4) * 0.22 + (Math.random() - 0.5) * 0.1;
      const nodeDist = clusterDist + 95 + ((idx * 17) % 75);

      list.push({
        id: `node_${idx}`,
        label: sub,
        type: 'host',
        clusterId: targetCluster,
        category,
        isAlive,
        isHttpLive,
        isDnsOnly,
        isBlocked,
        aliveInfo,
        x: Math.cos(spreadAngle) * nodeDist,
        y: Math.sin(spreadAngle) * nodeDist,
        radius: isHttpLive ? 7 : isAlive ? 6 : 5,
        color: nodeColor,
      });
    });

    return list;
  }, [subdomains, aliveHosts, domain]);

  // Canvas drawing loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId;
    let anglePulse = 0;

    const render = () => {
      anglePulse += 0.03;
      const width = canvas.width;
      const height = canvas.height;
      const cx = width / 2;
      const cy = height / 2;

      ctx.clearRect(0, 0, width, height);

      // Save transform
      ctx.save();
      ctx.translate(cx, cy);
      ctx.scale(zoom, zoom);

      // Draw connecting conduits (lines)
      nodes.forEach((node) => {
        if (node.type === 'cluster') {
          // Connect cluster to root
          ctx.beginPath();
          ctx.moveTo(0, 0);
          ctx.lineTo(node.x, node.y);
          ctx.strokeStyle = 'rgba(99, 102, 241, 0.25)';
          ctx.lineWidth = 1.5;
          ctx.stroke();
        } else if (node.type === 'host') {
          // Filter checks
          if (filterMode === 'live' && !node.isAlive) return;
          if (filterMode === 'hvt' && node.category === 'general') return;

          const parentCluster = nodes.find((n) => n.id === node.clusterId);
          if (parentCluster) {
            ctx.beginPath();
            ctx.moveTo(parentCluster.x, parentCluster.y);
            ctx.lineTo(node.x, node.y);
            ctx.strokeStyle = node.isAlive
              ? 'rgba(16, 185, 129, 0.28)'
              : 'rgba(71, 85, 105, 0.15)';
            ctx.lineWidth = node.isAlive ? 1 : 0.8;
            ctx.stroke();
          }
        }
      });

      // Draw Nodes
      nodes.forEach((node) => {
        if (node.type === 'host') {
          if (filterMode === 'live' && !node.isHttpLive) return;
          if (filterMode === 'hvt' && node.category === 'general') return;
        }

        const isSelected = selectedNode?.id === node.id;

        // Glowing ring for root or active nodes
        if (node.type === 'root') {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 8 + Math.sin(anglePulse) * 3, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(99, 102, 241, 0.15)';
          ctx.fill();
        } else if (node.isHttpLive) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 4 + Math.sin(anglePulse + node.x) * 2, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(16, 185, 129, 0.2)';
          ctx.fill();
        } else if (node.isBlocked) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 3, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(244, 63, 94, 0.25)';
          ctx.fill();
        }

        // Selected halo
        if (isSelected) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 6, 0, Math.PI * 2);
          ctx.strokeStyle = '#ffffff';
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = node.color;
        ctx.fill();
        ctx.strokeStyle = isSelected ? '#ffffff' : 'rgba(15, 23, 42, 0.8)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Node label
        if (node.type === 'root' || node.type === 'cluster' || isSelected) {
          ctx.font = node.type === 'root' ? 'bold 12px Plus Jakarta Sans, sans-serif' : '10px JetBrains Mono, monospace';
          ctx.fillStyle = '#ffffff';
          ctx.textAlign = 'center';
          ctx.fillText(node.label, node.x, node.y + node.radius + 14);
        }
      });

      ctx.restore();
      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [nodes, filterMode, zoom, selectedNode]);

  // Click on canvas to select node
  const handleCanvasClick = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;

    const clickX = (e.clientX - rect.left - cx) / zoom;
    const clickY = (e.clientY - rect.top - cy) / zoom;

    // Find clicked node
    let clicked = null;
    for (const node of nodes) {
      if (node.type === 'host') {
        if (filterMode === 'live' && !node.isAlive) continue;
        if (filterMode === 'hvt' && node.category === 'general') continue;
      }
      const dist = Math.hypot(clickX - node.x, clickY - node.y);
      if (dist <= node.radius + 6) {
        clicked = node;
        break;
      }
    }

    setSelectedNode(clicked);
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="bg-[#161822] border border-[#262b3b] rounded-2xl overflow-hidden shadow-2xl flex flex-col h-[580px] relative animate-fade-in">
      {/* Top Toolbar */}
      <div className="p-3 bg-[#11131b] border-b border-[#232733] flex flex-wrap items-center justify-between gap-3 z-10">
        <div className="flex items-center space-x-2">
          <Layers className="w-4 h-4 text-indigo-400" />
          <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
            Topology Constellation
          </h3>
          <span className="text-[11px] font-mono text-slate-400">
            [{nodes.filter((n) => n.type === 'host').length} nodes mapped]
          </span>
        </div>

        {/* Filters & Zoom */}
        <div className="flex items-center space-x-2 text-xs font-mono">
          <div className="flex rounded-lg bg-[#0e1017] p-0.5 border border-[#232733]">
            <button
              onClick={() => setFilterMode('all')}
              className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
                filterMode === 'all' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
              }`}
            >
              All Nodes
            </button>
            <button
              onClick={() => setFilterMode('live')}
              className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
                filterMode === 'live' ? 'bg-emerald-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
              }`}
            >
              HTTP Live
            </button>
            <button
              onClick={() => setFilterMode('hvt')}
              className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
                filterMode === 'hvt' ? 'bg-amber-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
              }`}
            >
              High Value
            </button>
          </div>

          <div className="flex items-center space-x-1 pl-2 border-l border-slate-800">
            <button
              onClick={() => setZoom((z) => Math.min(2, z + 0.15))}
              className="p-1 rounded bg-[#0e1017] hover:bg-slate-800 text-slate-300"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(0.5, z - 0.15))}
              className="p-1 rounded bg-[#0e1017] hover:bg-slate-800 text-slate-300"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => { setZoom(1); setSelectedNode(null); }}
              className="p-1 rounded bg-[#0e1017] hover:bg-slate-800 text-slate-300"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Graph Viewport */}
      <div className="relative flex-1 bg-[#090b10] cursor-crosshair overflow-hidden">
        <canvas
          ref={canvasRef}
          width={900}
          height={520}
          onClick={handleCanvasClick}
          className="w-full h-full block"
        />

        {/* Legend Overlay */}
        <div className="absolute bottom-3 left-3 bg-[#0e1017]/90 backdrop-blur-md border border-[#232733] rounded-xl p-2.5 text-[11px] font-mono space-y-1.5 pointer-events-none">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-500 inline-block shadow-[0_0_6px_#6366f1]" />
            <span className="text-slate-300">Apex Target Hub</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block shadow-[0_0_6px_#10b981]" />
            <span className="text-slate-300">HTTP Responding Host</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-sky-400 inline-block shadow-[0_0_6px_#38bdf8]" />
            <span className="text-slate-300">DNS Only (No HTTP)</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-rose-500 inline-block shadow-[0_0_6px_#f43f5e]" />
            <span className="text-slate-300">Blocked Internal IP</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-slate-500 inline-block" />
            <span className="text-slate-400">Offline Subdomain</span>
          </div>
        </div>

        {/* Node Inspector Side Flyout */}
        {selectedNode && selectedNode.type === 'host' && (
          <div className="absolute top-3 right-3 w-80 bg-[#161822]/95 backdrop-blur-md border border-[#262b3b] rounded-xl p-4 shadow-2xl space-y-3 font-mono text-xs z-20 animate-fade-in">
            <div className="flex items-center justify-between pb-2 border-b border-[#232733]">
              <span className="font-semibold text-white uppercase text-[11px]">
                Node Telemetry
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div>
              <span className="text-slate-500 text-[10px]">HOST</span>
              <div className="text-sm font-bold text-white break-all">
                {selectedNode.label}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div>
                <span className="text-slate-500 text-[10px]">STATUS</span>
                <div className={selectedNode.isAlive ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                  {selectedNode.isAlive ? `${selectedNode.aliveInfo?.statusCode || 200} ONLINE` : 'OFFLINE'}
                </div>
              </div>

              <div>
                <span className="text-slate-500 text-[10px]">CATEGORY</span>
                <div className="text-indigo-400 font-bold uppercase text-[11px]">
                  {selectedNode.category || 'general'}
                </div>
              </div>
            </div>

            {selectedNode.aliveInfo?.techStack && (
              <div>
                <span className="text-slate-500 text-[10px]">TECHNOLOGY STACK</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.aliveInfo.techStack.map((t, i) => (
                    <span key={i} className="px-1.5 py-0.5 rounded bg-[#0e1017] text-indigo-300 border border-[#232733] text-[10px]">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {selectedNode.aliveInfo?.title && (
              <div>
                <span className="text-slate-500 text-[10px]">PAGE TITLE</span>
                <p className="text-slate-300 italic text-[11px] line-clamp-2">
                  "{selectedNode.aliveInfo.title}"
                </p>
              </div>
            )}

            <div className="pt-2 border-t border-[#232733] flex items-center justify-between">
              <button
                onClick={() => handleCopy(`https://${selectedNode.label}`)}
                className="px-2.5 py-1 rounded bg-[#0e1017] hover:bg-slate-800 text-slate-300 border border-[#232733] flex items-center space-x-1"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy URL'}</span>
              </button>

              <a
                href={`https://${selectedNode.label}`}
                target="_blank"
                rel="noopener noreferrer"
                className="px-2.5 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white flex items-center space-x-1 font-semibold"
              >
                <span>Open</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
