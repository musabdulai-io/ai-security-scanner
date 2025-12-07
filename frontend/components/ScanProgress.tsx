'use client';

import { useMemo, useState, useRef, useEffect } from 'react';
import { Box, LinearProgress, Paper, Typography, Button } from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import BlockIcon from '@mui/icons-material/Block';
import AutorenewIcon from '@mui/icons-material/Autorenew';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import ShieldIcon from '@mui/icons-material/Shield';
import SpeedIcon from '@mui/icons-material/Speed';
import AttachMoneyIcon from '@mui/icons-material/AttachMoney';
import TerminalIcon from '@mui/icons-material/Terminal';
import AssessmentIcon from '@mui/icons-material/Assessment';
import CircularProgress from '@mui/material/CircularProgress';
import {
  type AttackState,
  type AttackCategory,
  type AttackStatus,
  createInitialAttackState,
  parseLogMessage,
  getCategoryProgress,
  getOverallProgress,
  getCurrentAttack,
} from '@/lib/attacks';

// Colors matching the existing theme
const colors = {
  passed: '#00ff88',
  failed: '#ff4444',
  running: '#00bcd4',
  pending: '#666666',
  skipped: '#ffcc00',
  error: '#ff8c00',
  security: '#ff4444',
  reliability: '#ff8c00',
  cost: '#4488ff',
  cardBg: '#1e1e1e',
  border: '#333',
};

interface ScanProgressProps {
  logs: string[];
  isRunning: boolean;
}

// Terminal view - inline logs display
function TerminalView({ logs, isRunning }: { logs: string[]; isRunning: boolean }) {
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const getLineColor = (line: string) => {
    if (line.includes('[FAIL]') || line.includes('[ERROR]')) return colors.failed;
    if (line.includes('[PASS]')) return colors.passed;
    if (line.includes('[WARN]')) return '#ff8c00';
    if (line.includes('[SKIP]')) return '#ffcc00';
    return colors.running;
  };

  return (
    <Box
      ref={terminalRef}
      sx={{
        p: 2,
        height: 350,
        overflowY: 'auto',
        fontFamily: '"Monaco", "Menlo", "Consolas", monospace',
        fontSize: '0.875rem',
        lineHeight: 1.6,
        backgroundColor: '#0a0a0a',
        '&::-webkit-scrollbar': { width: 8 },
        '&::-webkit-scrollbar-track': { backgroundColor: '#1e1e1e' },
        '&::-webkit-scrollbar-thumb': { backgroundColor: '#444', borderRadius: 4 },
      }}
    >
      {logs.length === 0 ? (
        <Typography sx={{ color: 'text.secondary', fontStyle: 'italic' }}>
          Waiting for scan to start...
        </Typography>
      ) : (
        logs.map((line, index) => (
          <Box
            key={index}
            sx={{ color: getLineColor(line), whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
          >
            {line}
          </Box>
        ))
      )}
      {isRunning && (
        <Box
          sx={{
            display: 'inline-block',
            width: 8,
            height: 16,
            backgroundColor: colors.running,
            animation: 'blink 1s infinite',
            '@keyframes blink': {
              '0%, 50%': { opacity: 1 },
              '51%, 100%': { opacity: 0 },
            },
          }}
        />
      )}
    </Box>
  );
}

// Status icon component
function StatusIcon({ status, size = 16 }: { status: AttackStatus; size?: number }) {
  const iconSx = { fontSize: size };

  switch (status) {
    case 'passed':
      return <CheckCircleIcon sx={{ ...iconSx, color: colors.passed }} />;
    case 'failed':
      return <ErrorIcon sx={{ ...iconSx, color: colors.failed }} />;
    case 'error':
      return <WarningIcon sx={{ ...iconSx, color: colors.error }} />;
    case 'skipped':
      return <BlockIcon sx={{ ...iconSx, color: colors.skipped }} />;
    case 'running':
      return (
        <AutorenewIcon
          sx={{
            ...iconSx,
            color: colors.running,
            animation: 'spin 1s linear infinite',
            '@keyframes spin': {
              '0%': { transform: 'rotate(0deg)' },
              '100%': { transform: 'rotate(360deg)' },
            },
          }}
        />
      );
    default:
      return <RadioButtonUncheckedIcon sx={{ ...iconSx, color: colors.pending }} />;
  }
}

// Failures summary card - shown at top when there are failures
function FailuresSummary({ failedAttacks }: { failedAttacks: AttackState[] }) {
  if (failedAttacks.length === 0) return null;

  return (
    <Paper
      elevation={0}
      sx={{
        backgroundColor: 'rgba(255, 68, 68, 0.1)',
        border: `2px solid ${colors.failed}`,
        borderRadius: 2,
        p: 2,
        mb: 2,
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <ErrorIcon sx={{ color: colors.failed }} />
        <Typography variant='subtitle1' sx={{ fontWeight: 700, color: colors.failed }}>
          {failedAttacks.length} VULNERABILIT{failedAttacks.length === 1 ? 'Y' : 'IES'} FOUND
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
        {failedAttacks.map(attack => (
          <Typography
            key={attack.name}
            variant='body2'
            sx={{
              color: colors.failed,
              backgroundColor: 'rgba(255, 68, 68, 0.1)',
              px: 1,
              py: 0.25,
              borderRadius: 1,
              fontSize: '0.75rem',
            }}
          >
            {attack.name}
          </Typography>
        ))}
      </Box>
    </Paper>
  );
}

// Success card - shown when scan completes with no issues
function SuccessCard({ total }: { total: number }) {
  return (
    <Paper
      elevation={0}
      sx={{
        backgroundColor: 'rgba(0, 255, 136, 0.1)',
        border: `2px solid ${colors.passed}`,
        borderRadius: 2,
        p: 2,
        mb: 2,
        textAlign: 'center',
      }}
    >
      <CheckCircleIcon sx={{ fontSize: 40, color: colors.passed, mb: 0.5 }} />
      <Typography variant='subtitle1' sx={{ fontWeight: 700, color: colors.passed }}>
        NO VULNERABILITIES FOUND
      </Typography>
      <Typography variant='body2' sx={{ color: 'text.secondary' }}>
        All {total} security checks passed
      </Typography>
    </Paper>
  );
}

// Category card component
function CategoryCard({
  category,
  attacks,
  label,
  icon,
  color,
}: {
  category: AttackCategory;
  attacks: AttackState[];
  label: string;
  icon: React.ReactNode;
  color: string;
}) {
  const progress = getCategoryProgress(attacks, category);
  // FIX: Count failures from category attacks, not all attacks
  const failedCount = progress.attacks.filter(a => a.status === 'failed').length;
  const hasFailures = failedCount > 0;

  return (
    <Paper
      elevation={0}
      sx={{
        backgroundColor: colors.cardBg,
        border: hasFailures ? `2px solid ${colors.failed}` : `1px solid ${colors.border}`,
        borderRadius: 2,
        p: 2,
        mb: 2,
      }}
    >
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box sx={{ color }}>{icon}</Box>
          <Typography variant='subtitle2' sx={{ fontWeight: 600, textTransform: 'uppercase' }}>
            {label}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {hasFailures && (
            <Typography
              variant='caption'
              sx={{
                color: colors.failed,
                backgroundColor: 'rgba(255, 68, 68, 0.2)',
                px: 1,
                py: 0.25,
                borderRadius: 1,
                fontWeight: 700,
              }}
            >
              {failedCount} issue{failedCount > 1 ? 's' : ''}
            </Typography>
          )}
          <Typography variant='body2' sx={{ color: 'text.secondary' }}>
            {progress.completed}/{progress.total}
          </Typography>
        </Box>
      </Box>

      {/* Progress bar */}
      <LinearProgress
        variant='determinate'
        value={progress.percentage}
        sx={{
          height: 4,
          borderRadius: 2,
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          mb: 1.5,
          '& .MuiLinearProgress-bar': {
            backgroundColor: hasFailures ? colors.failed : color,
            borderRadius: 2,
            transition: 'transform 0.3s ease',
          },
        }}
      />

      {/* Attacks list - in execution order */}
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)' },
          gap: 0.5,
        }}
      >
        {progress.attacks.map(attack => (
          <Box
            key={attack.name}
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.5,
              py: 0.25,
              px: 0.5,
              borderRadius: 0.5,
              backgroundColor:
                attack.status === 'failed'
                  ? 'rgba(255, 68, 68, 0.1)'
                  : attack.status === 'running'
                    ? 'rgba(0, 188, 212, 0.1)'
                    : 'transparent',
            }}
          >
            <StatusIcon status={attack.status} size={14} />
            <Typography
              variant='caption'
              sx={{
                color:
                  attack.status === 'failed'
                    ? colors.failed
                    : attack.status === 'pending'
                      ? 'text.disabled'
                      : 'text.secondary',
                fontWeight: attack.status === 'failed' ? 600 : 400,
              }}
            >
              {attack.name}
            </Typography>
            {attack.latencyMs && (
              <Typography
                variant='caption'
                sx={{ color: 'text.disabled', ml: 'auto', fontSize: '0.65rem' }}
              >
                {attack.latencyMs}ms
              </Typography>
            )}
          </Box>
        ))}
      </Box>
    </Paper>
  );
}

// Main ScanProgress component
export function ScanProgress({ logs, isRunning }: ScanProgressProps) {
  const [showLogs, setShowLogs] = useState(false);

  // Parse all logs to build current attack state
  const attackState = useMemo(() => {
    let state = createInitialAttackState();
    for (const log of logs) {
      state = parseLogMessage(log, state);
    }
    return state;
  }, [logs]);

  const overallProgress = useMemo(() => getOverallProgress(attackState), [attackState]);
  const currentAttack = useMemo(() => getCurrentAttack(attackState), [attackState]);
  const failedAttacks = useMemo(
    () => attackState.filter(a => a.status === 'failed'),
    [attackState],
  );
  const isComplete =
    !isRunning && overallProgress.completed === overallProgress.total && overallProgress.total > 0;

  // Don't render if no logs yet
  if (logs.length === 0 && !isRunning) {
    return null;
  }

  return (
    <Paper
      elevation={0}
      sx={{
        backgroundColor: '#0a0a0a',
        border: `1px solid ${colors.border}`,
        borderRadius: 2,
        overflow: 'hidden',
        maxWidth: 800,
        mx: 'auto',
        my: 4,
      }}
    >
      {/* Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          px: 2,
          py: 1.5,
          backgroundColor: colors.cardBg,
          borderBottom: `1px solid ${colors.border}`,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {isRunning && <CircularProgress size={18} sx={{ color: colors.running }} />}
          <Typography variant='subtitle1' sx={{ fontWeight: 600 }}>
            Security Scan {isComplete ? 'Complete' : 'Progress'}
          </Typography>
          {isRunning && currentAttack && (
            <Typography variant='caption' sx={{ color: colors.running }}>
              - {currentAttack}
            </Typography>
          )}
        </Box>
        <Button
          size='small'
          variant='outlined'
          startIcon={showLogs ? <AssessmentIcon /> : <TerminalIcon />}
          onClick={() => setShowLogs(!showLogs)}
          sx={{
            borderColor: colors.border,
            color: 'text.secondary',
            textTransform: 'none',
            '&:hover': { borderColor: 'text.secondary' },
          }}
        >
          {showLogs ? 'Progress' : 'Logs'}
        </Button>
      </Box>

      {/* Content */}
      {showLogs ? (
        <TerminalView logs={logs} isRunning={isRunning} />
      ) : (
        <Box sx={{ p: 2 }}>
          {/* Overall progress bar */}
          <Box sx={{ mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
              <Typography variant='body2' sx={{ color: 'text.secondary' }}>
                Overall Progress
              </Typography>
              <Typography variant='body2' sx={{ color: 'text.secondary' }}>
                {overallProgress.completed}/{overallProgress.total} attacks
              </Typography>
            </Box>
            <LinearProgress
              variant='determinate'
              value={overallProgress.percentage}
              sx={{
                height: 8,
                borderRadius: 4,
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
                '& .MuiLinearProgress-bar': {
                  backgroundColor: failedAttacks.length > 0 ? colors.failed : colors.passed,
                  borderRadius: 4,
                  transition: 'transform 0.3s ease',
                },
              }}
            />
          </Box>

          {/* Failures summary at top if there are failures */}
          {failedAttacks.length > 0 && <FailuresSummary failedAttacks={failedAttacks} />}

          {/* Success card if complete with no failures */}
          {isComplete && failedAttacks.length === 0 && (
            <SuccessCard total={overallProgress.total} />
          )}

          {/* Category cards */}
          <CategoryCard
            category='security'
            attacks={attackState}
            label='Security'
            icon={<ShieldIcon />}
            color={colors.security}
          />

          <CategoryCard
            category='reliability'
            attacks={attackState}
            label='Reliability'
            icon={<SpeedIcon />}
            color={colors.reliability}
          />

          <CategoryCard
            category='cost'
            attacks={attackState}
            label='Cost & Performance'
            icon={<AttachMoneyIcon />}
            color={colors.cost}
          />
        </Box>
      )}
    </Paper>
  );
}
