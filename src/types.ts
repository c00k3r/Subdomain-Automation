export interface LiveHost {
  url: string;
  subdomain: string;
  statusCode: number;
  title: string;
  latencyMs: number;
  ip?: string;
  server?: string;
}

export interface ScanData {
  id: string;
  domain: string;
  status: 'running' | 'completed' | 'failed';
  error?: string;
  startTime: number;
  endTime?: number;
  executionTime?: number;
  step: number;
  currentAction: string;
  totalSubdomains: number;
  aliveCount: number;
  subdomains: string[];
  aliveHosts: LiveHost[];
  logs: string[];
  files: {
    subdomainsTxt: string;
    aliveTxt: string;
    summaryTxt: string;
    reportMd: string;
    reconLog: string;
  };
}

export interface ScanSummaryItem {
  id: string;
  domain: string;
  status: 'running' | 'completed' | 'failed';
  startTime: number;
  endTime?: number;
  executionTime?: number;
  totalSubdomains: number;
  aliveCount: number;
}
