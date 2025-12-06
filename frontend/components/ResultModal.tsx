'use client';

import {
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import DownloadIcon from '@mui/icons-material/Download';
import TerminalIcon from '@mui/icons-material/Terminal';
import ShieldIcon from '@mui/icons-material/Shield';
import SpeedIcon from '@mui/icons-material/Speed';
import AttachMoneyIcon from '@mui/icons-material/AttachMoney';
import type { ScanResult, SeverityLevel, AttackResult, AttackCategory } from '@/lib/api';

interface ResultModalProps {
  open: boolean;
  onClose: () => void;
  result: ScanResult | null;
  onShowCLI: () => void;
}

const severityColors: Record<SeverityLevel, string> = {
  CRITICAL: '#ff4444',
  HIGH: '#ff8c00',
  MEDIUM: '#ffcc00',
  LOW: '#4488ff',
};

const statusColors: Record<string, string> = {
  FAIL: '#ff4444',
  ERROR: '#ff8c00',
  PASS: '#00ff88',
};

const categoryConfig: Record<
  AttackCategory,
  { label: string; color: string; icon: React.ReactNode }
> = {
  security: { label: 'Security', color: '#ff4444', icon: <ShieldIcon sx={{ fontSize: 16 }} /> },
  reliability: {
    label: 'Reliability',
    color: '#ff8c00',
    icon: <SpeedIcon sx={{ fontSize: 16 }} />,
  },
  cost: { label: 'Cost', color: '#4488ff', icon: <AttachMoneyIcon sx={{ fontSize: 16 }} /> },
};

// Group attacks by category
const groupAttacksByCategory = (attacks: AttackResult[]) => {
  const security = attacks.filter(a => a.category === 'security');
  const reliability = attacks.filter(a => a.category === 'reliability');
  const cost = attacks.filter(a => a.category === 'cost');
  return { security, reliability, cost };
};

// Sort attacks: FAIL first, then ERROR, then PASS
const sortAttacks = (attacks: AttackResult[]) => {
  const order: Record<string, number> = { FAIL: 0, ERROR: 1, PASS: 2 };
  return [...attacks].sort((a, b) => order[a.status] - order[b.status]);
};

export function ResultModal({ open, onClose, result, onShowCLI }: ResultModalProps) {
  if (!result) return null;

  const hasVulnerabilities = result.vulnerabilities.length > 0;

  // Count by severity
  const severityCounts = result.vulnerabilities.reduce(
    (acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    },
    {} as Record<SeverityLevel, number>,
  );

  const handleDownloadReport = () => {
    // Generate a simple HTML report from the result
    const html = generateReportHTML(result);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-report-${result.scan_id.slice(0, 8)}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth='sm'
      fullWidth
      PaperProps={{
        sx: {
          backgroundColor: 'background.paper',
          backgroundImage: 'none',
        },
      }}
    >
      <DialogTitle
        sx={{
          textAlign: 'center',
          pb: 1,
        }}
      >
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'center',
            mb: 2,
          }}
        >
          {hasVulnerabilities ? (
            <ErrorIcon sx={{ fontSize: 64, color: 'error.main' }} />
          ) : (
            <CheckCircleIcon sx={{ fontSize: 64, color: 'success.main' }} />
          )}
        </Box>
        <Typography
          variant='h5'
          sx={{
            color: hasVulnerabilities ? 'error.main' : 'success.main',
            fontWeight: 700,
          }}
        >
          {hasVulnerabilities ? 'Vulnerabilities Detected' : 'Scan Passed'}
        </Typography>
      </DialogTitle>

      <DialogContent>
        {/* Vulnerability Count */}
        <Box
          sx={{
            textAlign: 'center',
            mb: 3,
          }}
        >
          <Typography
            variant='h2'
            sx={{
              fontSize: '3rem',
              fontWeight: 700,
              color: hasVulnerabilities ? 'error.main' : 'success.main',
            }}
          >
            {result.vulnerabilities.length}
          </Typography>
          <Typography color='text.secondary'>
            {result.vulnerabilities.length === 1 ? 'vulnerability found' : 'vulnerabilities found'}
          </Typography>
        </Box>

        {/* Severity Badges */}
        {hasVulnerabilities && (
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'center',
              gap: 1,
              mb: 3,
              flexWrap: 'wrap',
            }}
          >
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as SeverityLevel[]).map(severity =>
              severityCounts[severity] ? (
                <Chip
                  key={severity}
                  label={`${severity}: ${severityCounts[severity]}`}
                  size='small'
                  sx={{
                    backgroundColor: `${severityColors[severity]}20`,
                    color: severityColors[severity],
                    border: `1px solid ${severityColors[severity]}`,
                    fontWeight: 600,
                  }}
                />
              ) : null,
            )}
          </Box>
        )}

        <Divider sx={{ mb: 3 }} />

        {/* Scan Details */}
        <Box sx={{ mb: 3 }}>
          <Typography variant='body2' color='text.secondary' gutterBottom>
            Target: {result.target_url}
          </Typography>
          <Typography variant='body2' color='text.secondary' gutterBottom>
            Duration: {result.duration_seconds.toFixed(2)}s
          </Typography>
          <Typography variant='body2' color='text.secondary'>
            Scan ID: {result.scan_id.slice(0, 8)}...
          </Typography>
        </Box>

        {/* Attack Results by Category */}
        {result.attack_results && result.attack_results.length > 0 && (
          <>
            <Divider sx={{ mb: 2 }} />
            <Typography variant='subtitle2' sx={{ mb: 2, fontWeight: 600 }}>
              Attack Results
            </Typography>
            {(['security', 'reliability', 'cost'] as AttackCategory[]).map(category => {
              const categoryAttacks = sortAttacks(
                result.attack_results.filter(a => a.category === category),
              );
              if (categoryAttacks.length === 0) return null;
              const config = categoryConfig[category];
              return (
                <Box key={category} sx={{ mb: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <Box sx={{ color: config.color }}>{config.icon}</Box>
                    <Typography variant='body2' sx={{ fontWeight: 600, color: config.color }}>
                      {config.label}
                    </Typography>
                  </Box>
                  <TableContainer>
                    <Table size='small'>
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: 'text.secondary', py: 0.5 }}>Attack</TableCell>
                          <TableCell sx={{ color: 'text.secondary', py: 0.5 }} align='center'>
                            Status
                          </TableCell>
                          <TableCell sx={{ color: 'text.secondary', py: 0.5 }} align='center'>
                            Issues
                          </TableCell>
                          <TableCell sx={{ color: 'text.secondary', py: 0.5 }} align='right'>
                            Latency
                          </TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {categoryAttacks.map(attack => (
                          <TableRow key={attack.attack_type}>
                            <TableCell sx={{ py: 0.5 }}>{attack.attack_type}</TableCell>
                            <TableCell align='center' sx={{ py: 0.5 }}>
                              <Chip
                                label={attack.status}
                                size='small'
                                sx={{
                                  backgroundColor: `${statusColors[attack.status]}20`,
                                  color: statusColors[attack.status],
                                  fontWeight: 600,
                                  fontSize: '0.7rem',
                                  height: 20,
                                }}
                              />
                            </TableCell>
                            <TableCell align='center' sx={{ py: 0.5 }}>
                              {attack.vulnerabilities.length}
                            </TableCell>
                            <TableCell align='right' sx={{ py: 0.5 }}>
                              {attack.latency_ms}ms
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              );
            })}
          </>
        )}
      </DialogContent>

      <DialogActions
        sx={{
          flexDirection: 'column',
          gap: 1,
          px: 3,
          pb: 3,
        }}
      >
        <Button
          variant='contained'
          fullWidth
          startIcon={<DownloadIcon />}
          onClick={handleDownloadReport}
        >
          Download Report
        </Button>
        <Button variant='outlined' fullWidth startIcon={<TerminalIcon />} onClick={onShowCLI}>
          Scan Your Own App (CLI)
        </Button>
        <Button variant='text' fullWidth onClick={onClose}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function generateReportHTML(result: ScanResult): string {
  const severityColors: Record<SeverityLevel, string> = {
    CRITICAL: '#ff4444',
    HIGH: '#ff8c00',
    MEDIUM: '#ffcc00',
    LOW: '#4488ff',
  };

  const statusColorsHTML: Record<string, string> = {
    FAIL: '#ff4444',
    ERROR: '#ff8c00',
    PASS: '#00ff88',
  };

  const categoryLabels: Record<string, { label: string; color: string }> = {
    security: { label: 'Security', color: '#ff4444' },
    reliability: { label: 'Reliability', color: '#ff8c00' },
    cost: { label: 'Cost', color: '#4488ff' },
  };

  const vulnerabilitiesHTML = result.vulnerabilities
    .map(
      vuln => `
      <div style="background: #1e1e1e; border-radius: 8px; padding: 16px; margin-bottom: 16px; border-left: 4px solid ${severityColors[vuln.severity]};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h3 style="margin: 0; color: white;">${vuln.name}</h3>
          <span style="background: ${severityColors[vuln.severity]}20; color: ${severityColors[vuln.severity]}; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600;">${vuln.severity}</span>
        </div>
        <p style="color: #a0a0a0; margin-bottom: 12px;">${vuln.description}</p>
        <div style="background: #0a0a0a; padding: 12px; border-radius: 6px; margin-bottom: 12px;">
          <div style="color: #00ff88; font-size: 12px; margin-bottom: 4px;">Request</div>
          <pre style="color: white; margin: 0; white-space: pre-wrap; font-family: monospace;">${vuln.evidence_request}</pre>
        </div>
        <div style="background: #0a0a0a; padding: 12px; border-radius: 6px;">
          <div style="color: #00ff88; font-size: 12px; margin-bottom: 4px;">Response</div>
          <pre style="color: white; margin: 0; white-space: pre-wrap; font-family: monospace;">${vuln.evidence_response}</pre>
        </div>
      </div>
    `,
    )
    .join('');

  // Generate attack results table by category
  const attackResultsHTML =
    result.attack_results && result.attack_results.length > 0
      ? (['security', 'reliability', 'cost'] as const)
          .map(category => {
            const attacks = result.attack_results
              .filter(a => a.category === category)
              .sort((a, b) => {
                const order: Record<string, number> = { FAIL: 0, ERROR: 1, PASS: 2 };
                return order[a.status] - order[b.status];
              });
            if (attacks.length === 0) return '';
            const config = categoryLabels[category];
            return `
            <div style="margin-bottom: 24px;">
              <h3 style="color: ${config.color}; margin-bottom: 12px;">${config.label}</h3>
              <table style="width: 100%; border-collapse: collapse;">
                <thead>
                  <tr style="border-bottom: 1px solid #333;">
                    <th style="text-align: left; padding: 8px; color: #a0a0a0;">Attack</th>
                    <th style="text-align: center; padding: 8px; color: #a0a0a0;">Status</th>
                    <th style="text-align: center; padding: 8px; color: #a0a0a0;">Issues</th>
                    <th style="text-align: right; padding: 8px; color: #a0a0a0;">Latency</th>
                  </tr>
                </thead>
                <tbody>
                  ${attacks
                    .map(
                      attack => `
                    <tr style="border-bottom: 1px solid #222;">
                      <td style="padding: 8px; color: white;">${attack.attack_type}</td>
                      <td style="text-align: center; padding: 8px;">
                        <span style="background: ${statusColorsHTML[attack.status]}20; color: ${statusColorsHTML[attack.status]}; padding: 2px 8px; border-radius: 8px; font-size: 11px; font-weight: 600;">${attack.status}</span>
                      </td>
                      <td style="text-align: center; padding: 8px; color: white;">${attack.vulnerabilities.length}</td>
                      <td style="text-align: right; padding: 8px; color: #a0a0a0;">${attack.latency_ms}ms</td>
                    </tr>
                  `,
                    )
                    .join('')}
                </tbody>
              </table>
            </div>
          `;
          })
          .join('')
      : '';

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>AI Security Scan Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: white; padding: 40px; margin: 0; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { text-align: center; background: linear-gradient(135deg, #00ff88, #4488ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .status { text-align: center; padding: 24px; border-radius: 12px; margin-bottom: 24px; }
    .status.failed { background: rgba(255, 68, 68, 0.1); border: 1px solid #ff4444; }
    .status.passed { background: rgba(0, 255, 136, 0.1); border: 1px solid #00ff88; }
    .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .meta-item { background: #141414; padding: 16px; border-radius: 8px; }
    .meta-label { color: #a0a0a0; font-size: 12px; margin-bottom: 4px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>AI Security Scan Report</h1>
    <div class="status ${result.vulnerabilities.length > 0 ? 'failed' : 'passed'}">
      <h2 style="color: ${result.vulnerabilities.length > 0 ? '#ff4444' : '#00ff88'}; margin: 0;">
        ${result.vulnerabilities.length > 0 ? 'VULNERABILITIES DETECTED' : 'SCAN PASSED'}
      </h2>
      <div style="font-size: 48px; font-weight: bold; color: ${result.vulnerabilities.length > 0 ? '#ff4444' : '#00ff88'};">
        ${result.vulnerabilities.length}
      </div>
    </div>
    <div class="meta">
      <div class="meta-item"><div class="meta-label">Target</div>${result.target_url}</div>
      <div class="meta-item"><div class="meta-label">Scan ID</div>${result.scan_id.slice(0, 8)}...</div>
      <div class="meta-item"><div class="meta-label">Timestamp</div>${new Date(result.timestamp).toLocaleString()}</div>
      <div class="meta-item"><div class="meta-label">Duration</div>${result.duration_seconds.toFixed(2)}s</div>
    </div>
    ${attackResultsHTML ? `<h2>Attack Results</h2>${attackResultsHTML}` : ''}
    ${result.vulnerabilities.length > 0 ? `<h2>Vulnerability Details</h2>${vulnerabilitiesHTML}` : ''}
    <footer style="text-align: center; color: #a0a0a0; margin-top: 40px; padding-top: 20px; border-top: 1px solid #333;">
      Generated by AI Security Scanner
    </footer>
  </div>
</body>
</html>`;
}
