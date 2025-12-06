'use client';

import {
  Box,
  Button,
  TextField,
  Typography,
  CircularProgress,
  FormControlLabel,
  Switch,
  Tooltip,
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import HistoryIcon from '@mui/icons-material/History';
import LockIcon from '@mui/icons-material/Lock';

interface HeroSectionProps {
  sandboxUrl: string;
  onStartScan: () => void;
  isScanning: boolean;
  disabled?: boolean;
  cooldownSeconds?: number;
  hasPreviousResult?: boolean;
  previousResultAge?: string | null;
  onViewPreviousResult?: () => void;
}

export function HeroSection({
  sandboxUrl,
  onStartScan,
  isScanning,
  disabled = false,
  cooldownSeconds = 0,
  hasPreviousResult = false,
  previousResultAge = null,
  onViewPreviousResult,
}: HeroSectionProps) {
  const isDisabled = isScanning || disabled || cooldownSeconds > 0;

  const getButtonText = () => {
    if (isScanning) return 'Scanning...';
    if (cooldownSeconds > 0) return `Wait ${cooldownSeconds}s`;
    return 'Run Live Attack';
  };

  return (
    <Box
      sx={{
        textAlign: 'center',
        py: { xs: 6, md: 10 },
        px: 2,
      }}
    >
      {/* Icon */}
      <SecurityIcon
        sx={{
          fontSize: 64,
          color: 'primary.main',
          mb: 3,
        }}
      />

      {/* Title */}
      <Typography
        variant='h1'
        sx={{
          fontSize: { xs: '2rem', md: '3rem' },
          fontWeight: 700,
          mb: 2,
          background: 'linear-gradient(135deg, #00ff88, #4488ff)',
          backgroundClip: 'text',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
        }}
      >
        AI Security Scanner
      </Typography>

      {/* Subtitle */}
      <Typography
        variant='h2'
        sx={{
          fontSize: { xs: '1rem', md: '1.25rem' },
          color: 'text.secondary',
          mb: 4,
          maxWidth: 600,
          mx: 'auto',
        }}
      >
        Audit LLM and RAG applications for security, reliability, and cost vulnerabilities.
      </Typography>

      {/* Target URL Input */}
      <Box
        sx={{
          maxWidth: 500,
          mx: 'auto',
          mb: 2,
        }}
      >
        <TextField
          fullWidth
          value={sandboxUrl}
          label='Target URL (Sandbox)'
          variant='outlined'
          InputProps={{
            readOnly: true,
          }}
          sx={{
            '& .MuiOutlinedInput-root': {
              backgroundColor: 'background.paper',
            },
          }}
        />
      </Box>

      {/* Twin Toggle (Placeholder - disabled until secure-rag deployed) */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'center' }}>
        <Tooltip title='Secure RAG target coming soon' placement='bottom'>
          <FormControlLabel
            control={<Switch disabled checked={false} size='small' />}
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, opacity: 0.5 }}>
                <Typography variant='body2' color='text.secondary'>
                  Standard RAG
                </Typography>
                <LockIcon sx={{ fontSize: 14, color: 'text.disabled' }} />
                <Typography variant='caption' color='text.disabled'>
                  Secure RAG
                </Typography>
              </Box>
            }
            sx={{ opacity: 0.6 }}
          />
        </Tooltip>
      </Box>

      {/* Action Buttons */}
      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
        <Button
          variant='contained'
          size='large'
          onClick={onStartScan}
          disabled={isDisabled}
          startIcon={
            isScanning ? (
              <CircularProgress size={20} sx={{ color: 'inherit' }} />
            ) : (
              <PlayArrowIcon />
            )
          }
          sx={{
            px: 4,
            py: 1.5,
            fontSize: '1.1rem',
          }}
        >
          {getButtonText()}
        </Button>

        {hasPreviousResult && onViewPreviousResult && (
          <Button
            variant='outlined'
            size='large'
            onClick={onViewPreviousResult}
            disabled={isScanning}
            startIcon={<HistoryIcon />}
            sx={{
              px: 3,
              py: 1.5,
              fontSize: '1rem',
            }}
          >
            View Last Result {previousResultAge && `(${previousResultAge})`}
          </Button>
        )}
      </Box>
    </Box>
  );
}
