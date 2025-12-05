'use client';

import { useState, useCallback, useEffect } from 'react';
import { Box, Container, Typography, Alert } from '@mui/material';
import { HeroSection, TerminalUI, ResultModal, CLIInstructions } from '@/components';
import { startScan, createScanEventSource, type ScanResult } from '@/lib/api';
import { getEnv } from '@/lib/env';
import {
  canStartScan,
  recordScanAttempt,
  getRemainingCooldown,
  saveResult,
  loadResult,
  clearResult,
  getResultAge,
} from '@/lib/session';

export default function Home() {
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [showResult, setShowResult] = useState(false);
  const [showCLI, setShowCLI] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);
  const [hasPreviousResult, setHasPreviousResult] = useState(false);
  const [previousResultAge, setPreviousResultAge] = useState<string | null>(null);

  const sandboxUrl = getEnv('NEXT_PUBLIC_SANDBOX_URL');

  // Load previous result from localStorage on mount
  useEffect(() => {
    const stored = loadResult();
    if (stored) {
      setResult(stored.result);
      setHasPreviousResult(true);
      setPreviousResultAge(getResultAge());
    }
  }, []);

  // Update cooldown timer and result age
  useEffect(() => {
    const interval = setInterval(() => {
      const remaining = getRemainingCooldown();
      setCooldown(remaining);

      // Update result age if we have a stored result
      if (hasPreviousResult) {
        setPreviousResultAge(getResultAge());
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [hasPreviousResult]);

  const handleStartScan = useCallback(async () => {
    // Client-side rate limiting
    if (!canStartScan()) {
      setError(`Please wait ${getRemainingCooldown()} seconds before starting another scan`);
      return;
    }

    // Clear previous result
    clearResult();
    setHasPreviousResult(false);
    setPreviousResultAge(null);

    setIsScanning(true);
    setLogs([]);
    setResult(null);
    setError(null);
    recordScanAttempt();

    try {
      const { scan_id } = await startScan(sandboxUrl);
      const eventSource = createScanEventSource(scan_id);

      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === 'log') {
            setLogs((prev) => [...prev, data.message]);
          } else if (data.type === 'result') {
            setResult(data.data);
            saveResult(scan_id, data.data); // Persist to localStorage
            setShowResult(true);
            setIsScanning(false);
            eventSource.close();
          } else if (data.type === 'error') {
            setError(data.message);
            setIsScanning(false);
            eventSource.close();
          }
        } catch (e) {
          console.error('Failed to parse SSE message:', e);
        }
      };

      eventSource.onerror = () => {
        setError('Connection lost. Please try again.');
        setIsScanning(false);
        eventSource.close();
      };
    } catch (e: unknown) {
      const errorMessage =
        e instanceof Error
          ? e.message
          : 'Failed to start scan. Please try again.';

      // Check for axios error response
      if (typeof e === 'object' && e !== null && 'response' in e) {
        const axiosError = e as { response?: { data?: { error?: string } } };
        if (axiosError.response?.data?.error) {
          setError(axiosError.response.data.error);
        } else {
          setError(errorMessage);
        }
      } else {
        setError(errorMessage);
      }

      setIsScanning(false);
    }
  }, [sandboxUrl]);

  const handleViewPreviousResult = useCallback(() => {
    if (result) {
      setShowResult(true);
    }
  }, [result]);

  return (
    <Box
      sx={{
        minHeight: '100vh',
        backgroundColor: 'background.default',
      }}
    >
      <Container maxWidth="lg">
        <HeroSection
          sandboxUrl={sandboxUrl}
          onStartScan={handleStartScan}
          isScanning={isScanning}
          cooldownSeconds={cooldown}
          hasPreviousResult={hasPreviousResult}
          previousResultAge={previousResultAge}
          onViewPreviousResult={handleViewPreviousResult}
        />

        {error && (
          <Alert
            severity="error"
            onClose={() => setError(null)}
            sx={{ maxWidth: 600, mx: 'auto', mb: 2 }}
          >
            {error}
          </Alert>
        )}

        {(isScanning || logs.length > 0) && (
          <TerminalUI logs={logs} isRunning={isScanning} />
        )}

        <ResultModal
          open={showResult}
          onClose={() => setShowResult(false)}
          result={result}
          onShowCLI={() => {
            setShowResult(false);
            setShowCLI(true);
          }}
        />

        <CLIInstructions open={showCLI} onClose={() => setShowCLI(false)} />

        {/* Footer */}
        <Box
          component="footer"
          sx={{
            textAlign: 'center',
            py: 4,
            color: 'text.secondary',
          }}
        >
          <Typography variant="body2">
            Built by{' '}
            <a
              href="https://musabdulai.com"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: '#00ff88' }}
            >
              Musah Abdulai
            </a>
            {' | '}
            <a
              href="https://github.com/musabdulai-io/ai-security-scanner"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: '#00ff88' }}
            >
              GitHub
            </a>
          </Typography>
        </Box>
      </Container>
    </Box>
  );
}
