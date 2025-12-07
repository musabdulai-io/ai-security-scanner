'use client';

import { useState } from 'react';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  LinearProgress,
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
import CalendarTodayIcon from '@mui/icons-material/CalendarToday';
import ShieldIcon from '@mui/icons-material/Shield';
import SpeedIcon from '@mui/icons-material/Speed';
import AttachMoneyIcon from '@mui/icons-material/AttachMoney';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import CloseIcon from '@mui/icons-material/Close';
import type { ScanResult, SeverityLevel, AttackCategory, Vulnerability } from '@/lib/api';

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
  security: { label: 'Security', color: '#ff4444', icon: <ShieldIcon sx={{ fontSize: 18 }} /> },
  reliability: {
    label: 'Reliability',
    color: '#ff8c00',
    icon: <SpeedIcon sx={{ fontSize: 18 }} />,
  },
  cost: { label: 'Cost', color: '#4488ff', icon: <AttachMoneyIcon sx={{ fontSize: 18 }} /> },
};

// Get risk level based on severity counts
const getRiskLevel = (severityCounts: Record<SeverityLevel, number>) => {
  if (severityCounts.CRITICAL > 0) return { label: 'CRITICAL RISK', color: '#ff4444' };
  if (severityCounts.HIGH > 0) return { label: 'HIGH RISK', color: '#ff8c00' };
  if (severityCounts.MEDIUM > 0) return { label: 'MODERATE RISK', color: '#ffcc00' };
  if (severityCounts.LOW > 0) return { label: 'LOW RISK', color: '#4488ff' };
  return { label: 'SECURE', color: '#00ff88' };
};

// Sort attacks: FAIL first, then ERROR, then PASS
const sortAttacks = <T extends { status: string }>(attacks: T[]): T[] => {
  const order: Record<string, number> = { FAIL: 0, ERROR: 1, PASS: 2 };
  return [...attacks].sort((a, b) => order[a.status] - order[b.status]);
};

export function ResultModal({ open, onClose, result, onShowCLI }: ResultModalProps) {
  // Expand first vulnerability by default if there are any
  const [expandedVuln, setExpandedVuln] = useState<string | false>(
    result?.vulnerabilities?.[0] ? `${result.vulnerabilities[0].name}-0` : false,
  );

  if (!result) return null;

  const hasVulnerabilities = result.vulnerabilities.length > 0;
  const vulnCount = result.vulnerabilities.length;

  // Count by severity
  const severityCounts = result.vulnerabilities.reduce(
    (acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    },
    {} as Record<SeverityLevel, number>,
  );

  // Count by category
  const categoryCounts = (result.attack_results || []).reduce(
    (acc, attack) => {
      acc[attack.category] = (acc[attack.category] || 0) + attack.vulnerabilities.length;
      return acc;
    },
    {} as Record<AttackCategory, number>,
  );

  const handleDownloadReport = () => {
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
      slotProps={{
        backdrop: {
          sx: {
            backgroundColor: 'rgba(0, 0, 0, 0.85)',
            backdropFilter: 'blur(4px)',
          },
        },
      }}
      PaperProps={{
        sx: {
          backgroundColor: 'background.paper',
          backgroundImage: 'none',
          maxHeight: '90vh',
        },
      }}
    >
      <DialogTitle sx={{ textAlign: 'center', pb: 1, position: 'relative' }}>
        {/* Close X button */}
        <IconButton
          onClick={onClose}
          sx={{
            position: 'absolute',
            right: 8,
            top: 8,
            color: 'text.secondary',
            '&:hover': { color: 'text.primary' },
          }}
          aria-label='close'
        >
          <CloseIcon />
        </IconButton>

        <Box sx={{ display: 'flex', justifyContent: 'center', mb: 1 }}>
          {hasVulnerabilities ? (
            <ErrorIcon sx={{ fontSize: 48, color: 'error.main' }} />
          ) : (
            <CheckCircleIcon sx={{ fontSize: 48, color: 'success.main' }} />
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

      <DialogContent sx={{ pt: 0 }}>
        {/* Vulnerability Count */}
        {(() => {
          const riskLevel = getRiskLevel(severityCounts);
          return (
            <Box
              sx={{
                background: 'rgba(255,255,255,0.03)',
                borderRadius: 2,
                p: 2,
                mb: 2,
                border: `1px solid ${riskLevel.color}30`,
                textAlign: 'center',
              }}
            >
              <Typography variant='h3' sx={{ color: riskLevel.color, fontWeight: 700 }}>
                {vulnCount}
              </Typography>
              <Typography variant='body2' color='text.secondary'>
                vulnerabilit{vulnCount === 1 ? 'y' : 'ies'} found
              </Typography>
              <Typography
                variant='caption'
                sx={{ color: riskLevel.color, fontWeight: 600, mt: 0.5, display: 'block' }}
              >
                {riskLevel.label}
              </Typography>
            </Box>
          );
        })()}

        {/* Category Summary */}
        <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
          {(['security', 'reliability', 'cost'] as AttackCategory[]).map(category => {
            const count = categoryCounts[category] || 0;
            const config = categoryConfig[category];
            return (
              <Box
                key={category}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 0.5,
                  px: 1.5,
                  py: 0.5,
                  borderRadius: 1,
                  backgroundColor: count > 0 ? `${config.color}15` : 'rgba(255,255,255,0.05)',
                  border: `1px solid ${count > 0 ? config.color : 'transparent'}30`,
                }}
              >
                <Box sx={{ color: config.color, display: 'flex' }}>{config.icon}</Box>
                <Typography
                  variant='body2'
                  sx={{ color: count > 0 ? config.color : 'text.secondary' }}
                >
                  {config.label}: {count}
                </Typography>
              </Box>
            );
          })}
        </Box>

        {/* Severity Badges */}
        {hasVulnerabilities && (
          <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
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
                    fontSize: '0.7rem',
                  }}
                />
              ) : null,
            )}
          </Box>
        )}

        {/* Vulnerabilities Found (Expandable) - MOVED TO TOP */}
        {hasVulnerabilities && (
          <>
            <Divider sx={{ my: 2 }} />
            <Typography variant='subtitle2' sx={{ mb: 1, fontWeight: 600, color: 'error.main' }}>
              Vulnerabilities Found
            </Typography>
            {result.vulnerabilities.map((vuln, idx) => (
              <Accordion
                key={`${vuln.name}-${idx}`}
                expanded={expandedVuln === `${vuln.name}-${idx}`}
                onChange={(_, isExpanded) =>
                  setExpandedVuln(isExpanded ? `${vuln.name}-${idx}` : false)
                }
                sx={{
                  backgroundColor: 'transparent',
                  boxShadow: 'none',
                  '&:before': { display: 'none' },
                  border: `1px solid ${severityColors[vuln.severity]}30`,
                  borderRadius: '4px !important',
                  mb: 1,
                  '&.Mui-expanded': { margin: '0 0 8px 0' },
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon sx={{ color: 'text.secondary' }} />}
                  sx={{ minHeight: 40, '& .MuiAccordionSummary-content': { margin: '8px 0' } }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                    <Typography variant='body2' sx={{ fontWeight: 500, flex: 1 }}>
                      {vuln.name}
                    </Typography>
                    <Chip
                      label={vuln.severity}
                      size='small'
                      sx={{
                        backgroundColor: `${severityColors[vuln.severity]}20`,
                        color: severityColors[vuln.severity],
                        fontWeight: 600,
                        fontSize: '0.65rem',
                        height: 18,
                      }}
                    />
                  </Box>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 0 }}>
                  <Typography
                    variant='body2'
                    color='text.secondary'
                    sx={{ fontSize: '0.8rem', mb: 2 }}
                  >
                    {vuln.description}
                  </Typography>

                  {/* Evidence */}
                  <Box sx={{ backgroundColor: 'rgba(0,0,0,0.3)', borderRadius: 1, p: 1.5, mb: 1 }}>
                    <Typography variant='caption' sx={{ color: '#00ff88', fontWeight: 600 }}>
                      Attack Prompt
                    </Typography>
                    <Typography
                      variant='body2'
                      sx={{
                        fontFamily: 'monospace',
                        fontSize: '0.75rem',
                        whiteSpace: 'pre-wrap',
                        mt: 0.5,
                        color: 'text.secondary',
                        wordBreak: 'break-word',
                      }}
                    >
                      {vuln.evidence_request}
                    </Typography>
                  </Box>

                  <Box sx={{ backgroundColor: 'rgba(0,0,0,0.3)', borderRadius: 1, p: 1.5 }}>
                    <Typography variant='caption' sx={{ color: '#ff4444', fontWeight: 600 }}>
                      Vulnerable Response
                    </Typography>
                    <Typography
                      variant='body2'
                      sx={{
                        fontFamily: 'monospace',
                        fontSize: '0.75rem',
                        whiteSpace: 'pre-wrap',
                        mt: 0.5,
                        color: 'text.secondary',
                        wordBreak: 'break-word',
                      }}
                    >
                      {vuln.evidence_response}
                    </Typography>
                  </Box>
                </AccordionDetails>
              </Accordion>
            ))}
          </>
        )}

        <Divider sx={{ my: 2 }} />

        {/* Attack Results Table */}
        {result.attack_results && result.attack_results.length > 0 && (
          <Box sx={{ mb: 2 }}>
            <Typography variant='subtitle2' sx={{ mb: 1.5, fontWeight: 600 }}>
              Attack Results
            </Typography>
            {(['security', 'reliability', 'cost'] as AttackCategory[]).map(category => {
              const categoryAttacks = sortAttacks(
                result.attack_results.filter(a => a.category === category),
              );
              if (categoryAttacks.length === 0) return null;
              const config = categoryConfig[category];
              return (
                <Box key={category} sx={{ mb: 1.5 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                    <Box sx={{ color: config.color, display: 'flex' }}>{config.icon}</Box>
                    <Typography variant='caption' sx={{ fontWeight: 600, color: config.color }}>
                      {config.label}
                    </Typography>
                  </Box>
                  <TableContainer>
                    <Table size='small'>
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: 'text.secondary', py: 0.5, fontSize: '0.75rem' }}>
                            Attack
                          </TableCell>
                          <TableCell
                            sx={{ color: 'text.secondary', py: 0.5, fontSize: '0.75rem' }}
                            align='center'
                          >
                            Status
                          </TableCell>
                          <TableCell
                            sx={{ color: 'text.secondary', py: 0.5, fontSize: '0.75rem' }}
                            align='center'
                          >
                            Issues
                          </TableCell>
                          <TableCell
                            sx={{ color: 'text.secondary', py: 0.5, fontSize: '0.75rem' }}
                            align='right'
                          >
                            Latency
                          </TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {categoryAttacks.map(attack => (
                          <TableRow key={attack.attack_type}>
                            <TableCell
                              sx={{
                                py: 0.5,
                                fontSize: '0.8rem',
                                color: attack.status === 'PASS' ? 'text.disabled' : 'text.primary',
                              }}
                            >
                              {attack.attack_type}
                            </TableCell>
                            <TableCell align='center' sx={{ py: 0.5 }}>
                              <Chip
                                label={attack.status}
                                size='small'
                                sx={{
                                  backgroundColor: `${statusColors[attack.status]}20`,
                                  color:
                                    attack.status === 'PASS'
                                      ? '#6b7280'
                                      : statusColors[attack.status],
                                  fontWeight: attack.status === 'FAIL' ? 700 : 400,
                                  fontSize: '0.65rem',
                                  height: 18,
                                }}
                              />
                            </TableCell>
                            <TableCell align='center' sx={{ py: 0.5, fontSize: '0.8rem' }}>
                              {attack.vulnerabilities.length}
                            </TableCell>
                            <TableCell
                              align='right'
                              sx={{ py: 0.5, fontSize: '0.8rem', color: 'text.secondary' }}
                            >
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
          </Box>
        )}

        <Divider sx={{ my: 2 }} />

        {/* Scan Details */}
        <Box>
          <Typography variant='subtitle2' sx={{ mb: 1, fontWeight: 600 }}>
            Scan Details
          </Typography>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
            <Typography variant='caption' color='text.secondary'>
              Target: {result.target_url}
            </Typography>
            <Typography variant='caption' color='text.secondary'>
              Duration: {result.duration_seconds.toFixed(2)}s
            </Typography>
            <Typography variant='caption' color='text.secondary'>
              Scan ID: {result.scan_id.slice(0, 8)}
            </Typography>
            <Typography variant='caption' color='text.secondary'>
              Time: {new Date(result.timestamp).toLocaleString()}
            </Typography>
          </Box>
        </Box>
      </DialogContent>

      <DialogActions sx={{ flexDirection: 'column', gap: 1, px: 3, pb: 3 }}>
        {hasVulnerabilities && (
          <Button
            variant='contained'
            fullWidth
            startIcon={<CalendarTodayIcon />}
            href='https://calendly.com/musabdulai/ai-security-check'
            target='_blank'
            rel='noopener noreferrer'
            sx={{
              background: 'linear-gradient(135deg, #00ff88, #4488ff)',
              color: '#000',
              fontWeight: 600,
              '&:hover': {
                background: 'linear-gradient(135deg, #00dd77, #3377ee)',
              },
            }}
          >
            Book a Call - Get Expert Help
          </Button>
        )}
        <Button
          variant={hasVulnerabilities ? 'outlined' : 'contained'}
          fullWidth
          startIcon={<DownloadIcon />}
          onClick={handleDownloadReport}
        >
          Download Full Report
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

  // Count severities for risk level
  const severityCounts = result.vulnerabilities.reduce(
    (acc, v) => {
      acc[v.severity] = (acc[v.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  // Determine risk level
  const getRiskLevel = () => {
    if (severityCounts.CRITICAL > 0) return { label: 'CRITICAL RISK', color: '#ff4444' };
    if (severityCounts.HIGH > 0) return { label: 'HIGH RISK', color: '#ff8c00' };
    if (severityCounts.MEDIUM > 0) return { label: 'MODERATE RISK', color: '#ffcc00' };
    if (severityCounts.LOW > 0) return { label: 'LOW RISK', color: '#4488ff' };
    return { label: 'SECURE', color: '#00ff88' };
  };
  const riskLevel = getRiskLevel();

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
      <div style="font-size: 48px; font-weight: bold; color: ${riskLevel.color};">
        ${result.vulnerabilities.length}
      </div>
      <div style="font-size: 14px; font-weight: 600; color: ${riskLevel.color}; margin-top: 8px;">
        ${riskLevel.label}
      </div>
    </div>

    <div class="meta">
      <div class="meta-item"><div class="meta-label">Target</div>${result.target_url}</div>
      <div class="meta-item"><div class="meta-label">Scan ID</div>${result.scan_id.slice(0, 8)}</div>
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
