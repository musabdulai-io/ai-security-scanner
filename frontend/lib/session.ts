/**
 * Client-side session management for rate limiting and result persistence.
 * Uses localStorage to prevent scan spamming and persist results.
 */

import type { ScanResult } from './api';

// Storage keys
const STORAGE_KEY = 'scanner_last_scan_time';
const RESULT_STORAGE_KEY = 'scanner_last_result';

// Timeouts
const COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes
const RESULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Result storage interface
export interface StoredResult {
  result: ScanResult;
  timestamp: number;
  scanId: string;
}

/**
 * Check if a new scan can be started based on cooldown period.
 */
export function canStartScan(): boolean {
  if (typeof window === 'undefined') return true;

  const lastScanTime = localStorage.getItem(STORAGE_KEY);
  if (!lastScanTime) return true;

  const elapsed = Date.now() - parseInt(lastScanTime, 10);
  return elapsed >= COOLDOWN_MS;
}

/**
 * Get remaining cooldown time in seconds.
 */
export function getRemainingCooldown(): number {
  if (typeof window === 'undefined') return 0;

  const lastScanTime = localStorage.getItem(STORAGE_KEY);
  if (!lastScanTime) return 0;

  const elapsed = Date.now() - parseInt(lastScanTime, 10);
  const remaining = Math.max(0, COOLDOWN_MS - elapsed);
  return Math.ceil(remaining / 1000);
}

/**
 * Record a scan attempt timestamp.
 */
export function recordScanAttempt(): void {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEY, Date.now().toString());
}

/**
 * Clear the scan cooldown (for testing).
 */
export function clearCooldown(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(STORAGE_KEY);
}

// ============================================
// Result Persistence Functions
// ============================================

/**
 * Save scan result to localStorage.
 */
export function saveResult(scanId: string, result: ScanResult): void {
  if (typeof window === 'undefined') return;

  const stored: StoredResult = {
    result,
    timestamp: Date.now(),
    scanId,
  };

  localStorage.setItem(RESULT_STORAGE_KEY, JSON.stringify(stored));
}

/**
 * Load scan result from localStorage if not expired.
 */
export function loadResult(): StoredResult | null {
  if (typeof window === 'undefined') return null;

  const stored = localStorage.getItem(RESULT_STORAGE_KEY);
  if (!stored) return null;

  try {
    const parsed: StoredResult = JSON.parse(stored);

    // Check if expired (24 hours)
    if (Date.now() - parsed.timestamp > RESULT_TTL_MS) {
      localStorage.removeItem(RESULT_STORAGE_KEY);
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

/**
 * Clear stored result.
 */
export function clearResult(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(RESULT_STORAGE_KEY);
}

/**
 * Get time since last result was saved as human-readable string.
 */
export function getResultAge(): string | null {
  const stored = loadResult();
  if (!stored) return null;

  const ageMs = Date.now() - stored.timestamp;
  const minutes = Math.floor(ageMs / 60000);

  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;

  const hours = Math.floor(minutes / 60);
  return `${hours} hour${hours > 1 ? 's' : ''} ago`;
}
