'use client';

import { useState } from 'react';
import {
  Box,
  Button,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  Tab,
  Tabs,
  Typography,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckIcon from '@mui/icons-material/Check';

interface CLIInstructionsProps {
  open: boolean;
  onClose: () => void;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div role='tabpanel' hidden={value !== index}>
      {value === index && <Box sx={{ pt: 2 }}>{children}</Box>}
    </div>
  );
}

export function CLIInstructions({ open, onClose }: CLIInstructionsProps) {
  const [tab, setTab] = useState(0);
  const [copied, setCopied] = useState<string | null>(null);

  const handleCopy = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const pipxCommand = `pipx run git+https://github.com/musabdulai-io/ai-security-scanner scanner scan https://your-app.com`;
  const dockerCommand = `docker run --rm -it ghcr.io/musabdulai-io/ai-security-scanner scanner scan https://your-app.com`;
  const installCommand = `pipx install git+https://github.com/musabdulai-io/ai-security-scanner`;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth='md'
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
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <Typography variant='h6' component='span'>
          Scan Your Own App
        </Typography>
        <IconButton onClick={onClose} size='small'>
          <CloseIcon />
        </IconButton>
      </DialogTitle>

      <DialogContent>
        <Typography color='text.secondary' sx={{ mb: 3 }}>
          Use the CLI to scan any LLM/RAG application you have permission to test. Ensure you have
          written authorization before scanning third-party systems.
        </Typography>

        <Tabs
          value={tab}
          onChange={(_, v) => setTab(v)}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label='pipx (Recommended)' />
          <Tab label='Docker' />
          <Tab label='Install Globally' />
        </Tabs>

        <TabPanel value={tab} index={0}>
          <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
            Run directly without installation using pipx:
          </Typography>
          <CodeBlock code={pipxCommand} id='pipx' copied={copied} onCopy={handleCopy} />
          <Typography variant='body2' color='text.secondary' sx={{ mt: 2 }}>
            Requires: Python 3.11+ and pipx installed
          </Typography>
        </TabPanel>

        <TabPanel value={tab} index={1}>
          <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
            Run using Docker (no Python required):
          </Typography>
          <CodeBlock code={dockerCommand} id='docker' copied={copied} onCopy={handleCopy} />
        </TabPanel>

        <TabPanel value={tab} index={2}>
          <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
            Install globally for repeated use:
          </Typography>
          <CodeBlock code={installCommand} id='install' copied={copied} onCopy={handleCopy} />
          <Typography variant='body2' color='text.secondary' sx={{ mt: 2, mb: 2 }}>
            Then run scans with:
          </Typography>
          <CodeBlock
            code='scanner scan https://your-app.com --output report.html'
            id='usage'
            copied={copied}
            onCopy={handleCopy}
          />
        </TabPanel>

        <Box
          sx={{
            mt: 3,
            p: 2,
            backgroundColor: 'rgba(255, 140, 0, 0.1)',
            border: '1px solid rgba(255, 140, 0, 0.3)',
            borderRadius: 1,
          }}
        >
          <Typography variant='body2' sx={{ color: '#ff8c00' }}>
            <strong>Important:</strong> Only scan applications you own or have explicit written
            permission to test. Unauthorized scanning may violate laws and terms of service.
          </Typography>
        </Box>
      </DialogContent>
    </Dialog>
  );
}

interface CodeBlockProps {
  code: string;
  id: string;
  copied: string | null;
  onCopy: (text: string, id: string) => void;
}

function CodeBlock({ code, id, copied, onCopy }: CodeBlockProps) {
  const isCopied = copied === id;

  return (
    <Box
      sx={{
        position: 'relative',
        backgroundColor: '#0a0a0a',
        borderRadius: 1,
        p: 2,
        pr: 6,
        fontFamily: '"Monaco", "Menlo", "Consolas", monospace',
        fontSize: '0.875rem',
        overflow: 'auto',
      }}
    >
      <code style={{ color: '#00ff88' }}>{code}</code>
      <Button
        size='small'
        onClick={() => onCopy(code, id)}
        sx={{
          position: 'absolute',
          top: 8,
          right: 8,
          minWidth: 32,
          p: 0.5,
        }}
      >
        {isCopied ? (
          <CheckIcon sx={{ fontSize: 18, color: 'success.main' }} />
        ) : (
          <ContentCopyIcon sx={{ fontSize: 18 }} />
        )}
      </Button>
    </Box>
  );
}
