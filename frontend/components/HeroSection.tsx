'use client';

import { Box, Button, TextField, Typography, CircularProgress } from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import HistoryIcon from '@mui/icons-material/History';

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
        variant="h1"
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
        variant="h2"
        sx={{
          fontSize: { xs: '1rem', md: '1.25rem' },
          color: 'text.secondary',
          mb: 4,
          maxWidth: 600,
          mx: 'auto',
        }}
      >
        Audit LLM and RAG applications for security vulnerabilities.
        Test for prompt injection, RAG poisoning, and PII leakage.
      </Typography>

      {/* Target URL Input */}
      <Box
        sx={{
          maxWidth: 500,
          mx: 'auto',
          mb: 3,
        }}
      >
        <TextField
          fullWidth
          value={sandboxUrl}
          label="Target URL (Sandbox)"
          variant="outlined"
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

      {/* Action Buttons */}
      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
        <Button
          variant="contained"
          size="large"
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
            variant="outlined"
            size="large"
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

      {/* Info Text */}
      <Typography
        variant="body2"
        sx={{
          mt: 2,
          color: 'text.secondary',
          fontSize: '0.875rem',
        }}
      >
        Demo mode: Only scans the sandbox RAG application
      </Typography>
    </Box>
  );
}
