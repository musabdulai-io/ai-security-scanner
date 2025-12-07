/**
 * Attack definitions and log parsing utilities for scan progress tracking.
 */

export type AttackCategory = 'security' | 'reliability' | 'cost';
export type AttackStatus = 'pending' | 'running' | 'passed' | 'failed' | 'error' | 'skipped';

export interface AttackDefinition {
  name: string;
  category: AttackCategory;
}

export interface AttackState extends AttackDefinition {
  status: AttackStatus;
  latencyMs?: number;
}

// All attacks in order of execution (matches backend ScannerService)
export const ATTACK_DEFINITIONS: AttackDefinition[] = [
  // Security Attacks (15)
  { name: 'Prompt Injection', category: 'security' },
  { name: 'PII Leaking', category: 'security' },
  { name: 'RAG Poisoning', category: 'security' },
  { name: 'Prompt Extraction', category: 'security' },
  { name: 'Output Weaponization', category: 'security' },
  { name: 'Excessive Agency', category: 'security' },
  { name: 'Tool Abuse', category: 'security' },
  { name: 'Encoding Bypass', category: 'security' },
  { name: 'Structure Injection', category: 'security' },
  { name: 'Indirect Prompt Injection', category: 'security' },
  { name: 'Multi-Turn Jailbreak', category: 'security' },
  { name: 'Language Bypass', category: 'security' },
  { name: 'Many-Shot Jailbreak', category: 'security' },
  { name: 'Content Continuation', category: 'security' },
  { name: 'Refusal Bypass', category: 'security' },

  // Reliability Attacks (7)
  { name: 'Hallucination Detection', category: 'reliability' },
  { name: 'Table Parsing', category: 'reliability' },
  { name: 'Retrieval Precision', category: 'reliability' },
  { name: 'Competitor Trap', category: 'reliability' },
  { name: 'Pricing Trap', category: 'reliability' },
  { name: 'Off-Topic Handling', category: 'reliability' },
  { name: 'Brand Safety', category: 'reliability' },

  // Cost Attacks (2)
  { name: 'Efficiency Analysis', category: 'cost' },
  { name: 'Resource Exhaustion', category: 'cost' },
];

/**
 * Create initial attack state with all attacks pending.
 */
export function createInitialAttackState(): AttackState[] {
  return ATTACK_DEFINITIONS.map(def => ({
    ...def,
    status: 'pending' as AttackStatus,
  }));
}

/**
 * Update attack status by name.
 */
function updateAttackStatus(
  attacks: AttackState[],
  attackName: string,
  status: AttackStatus,
  latencyMs?: number,
): AttackState[] {
  return attacks.map(attack => {
    if (attack.name === attackName) {
      return { ...attack, status, latencyMs };
    }
    // If a new attack is running, mark the previous running one as its status
    // (shouldn't happen normally, but handle gracefully)
    return attack;
  });
}

/**
 * Parse a log message and update attack state accordingly.
 *
 * Log patterns:
 * - [INFO] Running Prompt Injection...
 * - [PASS] Prompt Injection: PASS (123ms)
 * - [FAIL] Prompt Injection: VULNERABLE (123ms)
 * - [SKIP] Skipping RAG Poisoning (fast mode)
 * - [ERROR] Prompt Injection: error message
 */
export function parseLogMessage(message: string, attacks: AttackState[]): AttackState[] {
  // Pattern: [INFO] Running Prompt Injection...
  const runningMatch = message.match(/\[INFO\] Running (.+)\.\.\./);
  if (runningMatch) {
    return updateAttackStatus(attacks, runningMatch[1], 'running');
  }

  // Pattern: [PASS] Prompt Injection: PASS (123ms)
  const passMatch = message.match(/\[PASS\] (.+): PASS \((\d+)ms\)/);
  if (passMatch) {
    return updateAttackStatus(attacks, passMatch[1], 'passed', parseInt(passMatch[2]));
  }

  // Pattern: [FAIL] Prompt Injection: VULNERABLE (123ms)
  const failMatch = message.match(/\[FAIL\] (.+): VULNERABLE \((\d+)ms\)/);
  if (failMatch) {
    return updateAttackStatus(attacks, failMatch[1], 'failed', parseInt(failMatch[2]));
  }

  // Pattern: [SKIP] Skipping RAG Poisoning (fast mode)
  const skipMatch = message.match(/\[SKIP\] Skipping (.+) \(fast mode\)/);
  if (skipMatch) {
    return updateAttackStatus(attacks, skipMatch[1], 'skipped');
  }

  // Pattern: [ERROR] Prompt Injection: error message
  const errorMatch = message.match(/\[ERROR\] (.+?): .+/);
  if (errorMatch) {
    return updateAttackStatus(attacks, errorMatch[1], 'error');
  }

  return attacks;
}

/**
 * Calculate progress stats for a category.
 */
export function getCategoryProgress(attacks: AttackState[], category: AttackCategory) {
  const categoryAttacks = attacks.filter(a => a.category === category);
  const completed = categoryAttacks.filter(a =>
    ['passed', 'failed', 'error', 'skipped'].includes(a.status),
  ).length;
  const total = categoryAttacks.length;
  const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;

  return { completed, total, percentage, attacks: categoryAttacks };
}

/**
 * Calculate overall progress.
 */
export function getOverallProgress(attacks: AttackState[]) {
  const completed = attacks.filter(a =>
    ['passed', 'failed', 'error', 'skipped'].includes(a.status),
  ).length;
  const total = attacks.length;
  const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;

  return { completed, total, percentage };
}

/**
 * Get the currently running attack name.
 */
export function getCurrentAttack(attacks: AttackState[]): string | null {
  const running = attacks.find(a => a.status === 'running');
  return running?.name ?? null;
}

/**
 * Count issues (failed attacks) by category.
 */
export function getIssuesByCategory(attacks: AttackState[]) {
  return {
    security: attacks.filter(a => a.category === 'security' && a.status === 'failed').length,
    reliability: attacks.filter(a => a.category === 'reliability' && a.status === 'failed').length,
    cost: attacks.filter(a => a.category === 'cost' && a.status === 'failed').length,
  };
}
