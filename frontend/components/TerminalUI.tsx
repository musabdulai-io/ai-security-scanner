'use client';

import { useEffect, useRef } from 'react';
import { Box, Paper, Typography } from '@mui/material';
import TerminalIcon from '@mui/icons-material/Terminal';

interface TerminalUIProps {
  logs: string[];
  isRunning: boolean;
}

export function TerminalUI({ logs, isRunning }: TerminalUIProps) {
  const terminalRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const getLineColor = (line: string) => {
    if (line.includes('[FAIL]') || line.includes('[ERROR]')) return '#ff4444';
    if (line.includes('[PASS]')) return '#00ff88';
    if (line.includes('[WARN]')) return '#ff8c00';
    if (line.includes('[SKIP]')) return '#ffcc00';
    return '#00ff88';
  };

  return (
    <Paper
      elevation={0}
      sx={{
        backgroundColor: '#0a0a0a',
        border: '1px solid #333',
        borderRadius: 2,
        overflow: 'hidden',
        maxWidth: 800,
        mx: 'auto',
        my: 4,
      }}
    >
      {/* Terminal Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          px: 2,
          py: 1,
          backgroundColor: '#1e1e1e',
          borderBottom: '1px solid #333',
        }}
      >
        <TerminalIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
        <Typography variant='body2' sx={{ color: 'text.secondary' }}>
          Security Scan Output
        </Typography>
        {isRunning && (
          <Box
            sx={{
              ml: 'auto',
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: '#00ff88',
              animation: 'pulse 1.5s infinite',
              '@keyframes pulse': {
                '0%, 100%': { opacity: 1 },
                '50%': { opacity: 0.5 },
              },
            }}
          />
        )}
      </Box>

      {/* Terminal Content */}
      <Box
        ref={terminalRef}
        sx={{
          p: 2,
          height: 300,
          overflowY: 'auto',
          fontFamily: '"Monaco", "Menlo", "Consolas", monospace',
          fontSize: '0.875rem',
          lineHeight: 1.6,
          '&::-webkit-scrollbar': {
            width: 8,
          },
          '&::-webkit-scrollbar-track': {
            backgroundColor: '#1e1e1e',
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: '#444',
            borderRadius: 4,
          },
        }}
      >
        {logs.length === 0 ? (
          <Typography
            sx={{
              color: 'text.secondary',
              fontStyle: 'italic',
            }}
          >
            Waiting for scan to start...
          </Typography>
        ) : (
          logs.map((line, index) => (
            <Box
              key={index}
              sx={{
                color: getLineColor(line),
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
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
              backgroundColor: '#00ff88',
              animation: 'blink 1s infinite',
              '@keyframes blink': {
                '0%, 50%': { opacity: 1 },
                '51%, 100%': { opacity: 0 },
              },
            }}
          />
        )}
      </Box>
    </Paper>
  );
}
