'use client';

import {
  Box,
  Button,
  TextField,
  Typography,
  CircularProgress,
  ToggleButton,
  ToggleButtonGroup,
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import HistoryIcon from '@mui/icons-material/History';
import GitHubIcon from '@mui/icons-material/GitHub';
import CalendarTodayIcon from '@mui/icons-material/CalendarToday';

interface HeroSectionProps {
  sandboxUrl: string;
  onStartScan: () => void;
  isScanning: boolean;
  disabled?: boolean;
  cooldownSeconds?: number;
  hasPreviousResult?: boolean;
  previousResultAge?: string | null;
  onViewPreviousResult?: () => void;
  ragMode: 'standard' | 'secure';
  onRagModeChange: (mode: 'standard' | 'secure') => void;
  llmJudge: boolean;
  onLlmJudgeChange: (enabled: boolean) => void;
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
  ragMode,
  onRagModeChange,
  llmJudge,
  onLlmJudgeChange,
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

      {/* Scan Options */}
      <Box sx={{ mb: 3, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
        {/* RAG Mode Toggle */}
        <Box sx={{ width: '100%', maxWidth: 400 }}>
          <Typography
            variant='caption'
            color='text.secondary'
            sx={{ mb: 1, display: 'block', textAlign: 'center' }}
          >
            Target
          </Typography>
          <ToggleButtonGroup
            value={ragMode}
            exclusive
            onChange={(_, value) => value && onRagModeChange(value)}
            size='small'
            disabled={isScanning}
            sx={{ width: '100%', display: 'flex' }}
          >
            <ToggleButton
              value='standard'
              sx={{
                flex: 1,
                py: 1,
                '&.Mui-selected': {
                  backgroundColor: 'rgba(0, 255, 136, 0.15)',
                  borderColor: 'primary.main',
                  '&:hover': { backgroundColor: 'rgba(0, 255, 136, 0.25)' },
                },
              }}
            >
              <Typography variant='body2'>Standard RAG</Typography>
            </ToggleButton>
            <ToggleButton
              value='secure'
              disabled
              sx={{
                flex: 1,
                py: 1,
                '&.Mui-disabled': { opacity: 0.5 },
              }}
            >
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant='body2'>Secure RAG</Typography>
                <Typography
                  variant='caption'
                  color='text.disabled'
                  sx={{ display: 'block', fontSize: '0.65rem' }}
                >
                  Coming soon
                </Typography>
              </Box>
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>

        {/* Detection Mode Toggle */}
        <Box sx={{ width: '100%', maxWidth: 400 }}>
          <Typography
            variant='caption'
            color='text.secondary'
            sx={{ mb: 1, display: 'block', textAlign: 'center' }}
          >
            Detection Mode
          </Typography>
          <ToggleButtonGroup
            value={llmJudge ? 'llm' : 'pattern'}
            exclusive
            onChange={(_, value) => value && onLlmJudgeChange(value === 'llm')}
            size='small'
            disabled={isScanning}
            sx={{ width: '100%', display: 'flex' }}
          >
            <ToggleButton
              value='pattern'
              sx={{
                flex: 1,
                py: 1,
                '&.Mui-selected': {
                  backgroundColor: 'rgba(0, 255, 136, 0.15)',
                  borderColor: 'primary.main',
                  '&:hover': { backgroundColor: 'rgba(0, 255, 136, 0.25)' },
                },
              }}
            >
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant='body2'>Pattern-based</Typography>
                <Typography
                  variant='caption'
                  color='text.secondary'
                  sx={{ display: 'block', fontSize: '0.65rem' }}
                >
                  Faster
                </Typography>
              </Box>
            </ToggleButton>
            <ToggleButton
              value='llm'
              sx={{
                flex: 1,
                py: 1,
                '&.Mui-selected': {
                  backgroundColor: 'rgba(0, 255, 136, 0.15)',
                  borderColor: 'primary.main',
                  '&:hover': { backgroundColor: 'rgba(0, 255, 136, 0.25)' },
                },
              }}
            >
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant='body2'>LLM Judge</Typography>
                <Typography
                  variant='caption'
                  color='text.secondary'
                  sx={{ display: 'block', fontSize: '0.65rem' }}
                >
                  More accurate
                </Typography>
              </Box>
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>
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

      {/* Self-host & CTA Footer */}
      <Box
        sx={{
          mt: 4,
          pt: 3,
          borderTop: '1px solid',
          borderColor: 'divider',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 1.5,
        }}
      >
        <Typography variant='body2' color='text.secondary'>
          Want to scan your own AI apps?
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', justifyContent: 'center' }}>
          <Button
            size='small'
            variant='outlined'
            startIcon={<GitHubIcon />}
            href='https://github.com/musabdulai-io/ai-security-scanner'
            target='_blank'
            rel='noopener noreferrer'
            sx={{
              borderColor: 'text.secondary',
              color: 'text.secondary',
              '&:hover': {
                borderColor: 'primary.main',
                color: 'primary.main',
              },
            }}
          >
            View on GitHub
          </Button>
          <Button
            size='small'
            variant='outlined'
            startIcon={<CalendarTodayIcon />}
            href='https://calendly.com/musabdulai/ai-security-check'
            target='_blank'
            rel='noopener noreferrer'
            sx={{
              borderColor: 'success.main',
              color: 'success.main',
              '&:hover': {
                borderColor: 'success.light',
                backgroundColor: 'rgba(0, 255, 136, 0.1)',
              },
            }}
          >
            Book a Call
          </Button>
        </Box>
      </Box>
    </Box>
  );
}
