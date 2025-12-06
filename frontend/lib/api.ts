/**
 * API client for the AI Security Scanner backend.
 */

import axios, { type AxiosInstance } from 'axios';
import { getEnv } from './env';

let apiInstance: AxiosInstance | null = null;

function getApiInstance(): AxiosInstance {
  if (!apiInstance) {
    apiInstance = axios.create({
      baseURL: `${getEnv('NEXT_PUBLIC_API_URL')}/api/v1`,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return apiInstance;
}

// Types
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AttackCategory = 'security' | 'reliability' | 'cost';

export interface Vulnerability {
  name: string;
  severity: SeverityLevel;
  description: string;
  evidence_request: string;
  evidence_response: string;
}

export interface AttackResult {
  attack_type: string;
  status: 'PASS' | 'FAIL' | 'ERROR';
  latency_ms: number;
  vulnerabilities: Vulnerability[];
  category: AttackCategory;
}

export interface ScanResult {
  target_url: string;
  scan_id: string;
  timestamp: string;
  duration_seconds: number;
  status: 'SUCCESS' | 'FAILED' | 'PARTIAL';
  vulnerabilities: Vulnerability[];
  attack_results: AttackResult[];
}

export interface ScanStartResponse {
  scan_id: string;
  message: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: string;
  progress: number;
  current_attack: string | null;
}

// API functions
export async function startScan(targetUrl: string, fast = false): Promise<ScanStartResponse> {
  const response = await getApiInstance().post<ScanStartResponse>('/scanner/scan/start', {
    target_url: targetUrl,
    fast,
  });
  return response.data;
}

export function createScanEventSource(scanId: string): EventSource {
  const apiUrl = getEnv('NEXT_PUBLIC_API_URL');
  return new EventSource(`${apiUrl}/api/v1/scanner/scan/${scanId}/stream`);
}

export async function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  const response = await getApiInstance().get<ScanStatusResponse>(`/scanner/scan/${scanId}/status`);
  return response.data;
}

export async function getScanResult(scanId: string): Promise<ScanResult> {
  const response = await getApiInstance().get<ScanResult>(`/scanner/scan/${scanId}/result`);
  return response.data;
}
