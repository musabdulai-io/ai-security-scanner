'use client';

import { useMemo, memo } from 'react';
import { Box, LinearProgress, Paper, Typography, Tooltip } from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import BlockIcon from '@mui/icons-material/Block';
import AutorenewIcon from '@mui/icons-material/Autorenew';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import ShieldIcon from '@mui/icons-material/Shield';
import SpeedIcon from '@mui/icons-material/Speed';
import AttachMoneyIcon from '@mui/icons-material/AttachMoney';
import {
  type AttackState,
  type AttackCategory,
  type AttackStatus,
  createInitialAttackState,
  parseLogMessage,
  getCategoryProgress,
  getOverallProgress,
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

interface CategoryCardProps {
  category: AttackCategory;
  attacks: AttackState[];
  label: string;
  icon: React.ReactNode;
  color: string;
}

interface AttackChipProps {
  attack: AttackState;
}

// Status icon component
function StatusIcon({ status }: { status: AttackStatus }) {
  const iconSx = { fontSize: 16 };

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

// Individual attack chip
const AttackChip = memo(function AttackChip({ attack }: AttackChipProps) {
  const isActive = attack.status === 'running';

  return (
    <Tooltip
      title={
        attack.latencyMs
          ? `${attack.status.toUpperCase()} (${attack.latencyMs}ms)`
          : attack.status.toUpperCase()
      }
      placement='top'
    >
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 0.5,
          px: 1,
          py: 0.5,
          borderRadius: 1,
          backgroundColor: isActive ? 'rgba(0, 188, 212, 0.1)' : 'transparent',
          border: isActive ? '1px solid rgba(0, 188, 212, 0.3)' : '1px solid transparent',
          transition: 'all 0.2s ease',
          minWidth: 0,
        }}
      >
        <StatusIcon status={attack.status} />
        <Typography
          variant='body2'
          sx={{
            fontSize: '0.75rem',
            color: attack.status === 'pending' ? 'text.disabled' : 'text.secondary',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {attack.name}
        </Typography>
      </Box>
    </Tooltip>
  );
});

// Category card component
const CategoryCard = memo(function CategoryCard({
  category,
  attacks,
  label,
  icon,
  color,
}: CategoryCardProps) {
  const progress = getCategoryProgress(attacks, category);
  const failedCount = attacks.filter(a => a.status === 'failed').length;

  return (
    <Paper
      elevation={0}
      sx={{
        backgroundColor: colors.cardBg,
        border: `1px solid ${colors.border}`,
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
          {failedCount > 0 && (
            <Typography
              variant='caption'
              sx={{
                color: colors.failed,
                backgroundColor: 'rgba(255, 68, 68, 0.1)',
                px: 1,
                py: 0.25,
                borderRadius: 1,
                fontWeight: 600,
              }}
            >
              {failedCount} issue{failedCount > 1 ? 's' : ''}
            </Typography>
          )}
        </Box>
        <Typography variant='body2' sx={{ color: 'text.secondary' }}>
          {progress.completed}/{progress.total}
        </Typography>
      </Box>

      {/* Progress bar */}
      <LinearProgress
        variant='determinate'
        value={progress.percentage}
        sx={{
          height: 6,
          borderRadius: 3,
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          mb: 1.5,
          '& .MuiLinearProgress-bar': {
            backgroundColor: color,
            borderRadius: 3,
            transition: 'transform 0.3s ease',
          },
        }}
      />

      {/* Attack chips grid */}
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: {
            xs: 'repeat(2, 1fr)',
            sm: 'repeat(3, 1fr)',
            md: 'repeat(4, 1fr)',
          },
          gap: 0.5,
        }}
      >
        {progress.attacks.map(attack => (
          <AttackChip key={attack.name} attack={attack} />
        ))}
      </Box>
    </Paper>
  );
});

// Overall progress footer
function OverallProgress({
  completed,
  total,
  percentage,
}: {
  completed: number;
  total: number;
  percentage: number;
}) {
  return (
    <Paper
      elevation={0}
      sx={{
        backgroundColor: colors.cardBg,
        border: `1px solid ${colors.border}`,
        borderRadius: 2,
        p: 2,
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
        <Typography variant='body2' sx={{ color: 'text.secondary' }}>
          Overall Progress
        </Typography>
        <Typography variant='body2' sx={{ color: 'text.secondary' }}>
          {completed}/{total} attacks complete
        </Typography>
      </Box>
      <LinearProgress
        variant='determinate'
        value={percentage}
        sx={{
          height: 8,
          borderRadius: 4,
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          '& .MuiLinearProgress-bar': {
            backgroundColor: colors.passed,
            borderRadius: 4,
            transition: 'transform 0.3s ease',
          },
        }}
      />
      <Typography
        variant='caption'
        sx={{ display: 'block', textAlign: 'center', mt: 1, color: 'text.secondary' }}
      >
        {percentage}%
      </Typography>
    </Paper>
  );
}

// Main ScanProgress component
export function ScanProgress({ logs, isRunning }: ScanProgressProps) {
  // Parse all logs to build current attack state
  const attackState = useMemo(() => {
    let state = createInitialAttackState();
    for (const log of logs) {
      state = parseLogMessage(log, state);
    }
    return state;
  }, [logs]);

  const overallProgress = useMemo(() => getOverallProgress(attackState), [attackState]);

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
        <Typography variant='subtitle1' sx={{ fontWeight: 600 }}>
          Security Scan Progress
        </Typography>
        {isRunning && (
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1,
            }}
          >
            <Box
              sx={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                backgroundColor: colors.running,
                animation: 'pulse 1.5s infinite',
                '@keyframes pulse': {
                  '0%, 100%': { opacity: 1 },
                  '50%': { opacity: 0.5 },
                },
              }}
            />
            <Typography variant='caption' sx={{ color: colors.running }}>
              Scanning...
            </Typography>
          </Box>
        )}
      </Box>

      {/* Content */}
      <Box sx={{ p: 2 }}>
        {/* Security Category */}
        <CategoryCard
          category='security'
          attacks={attackState}
          label='Security'
          icon={<ShieldIcon />}
          color={colors.security}
        />

        {/* Reliability Category */}
        <CategoryCard
          category='reliability'
          attacks={attackState}
          label='Reliability'
          icon={<SpeedIcon />}
          color={colors.reliability}
        />

        {/* Cost Category */}
        <CategoryCard
          category='cost'
          attacks={attackState}
          label='Cost & Performance'
          icon={<AttachMoneyIcon />}
          color={colors.cost}
        />

        {/* Overall Progress */}
        <OverallProgress {...overallProgress} />
      </Box>
    </Paper>
  );
}
