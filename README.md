# LLM Production Safety Scanner

A CLI tool for testing production safety controls in LLM and RAG applications. Tests for prompt injection, PII leakage, hallucinations, cost vulnerabilities, and more.

## Important Notice

**This is a local-only CLI tool.** There is no hosted service. Run scans against your own endpoints.

**Authorized testing only.** You must own the system or have explicit written permission before scanning. See [SECURITY.md](SECURITY.md) for responsible use guidelines.

## Get Started

- [View Sample Report](https://musabdulai.com/sample-report) - See what an audit report looks like
- [View on GitHub](https://github.com/musabdulai-io/llm-production-safety-scanner)
- [Book a Call](https://calendly.com/musabdulai/guardrails-sprint) - For custom scanning of your AI apps

## Who It's For

- Teams running RAG apps, agents, or chatbots in production
- Security engineers validating LLM safety controls
- Developers testing guardrails before deployment

## Editions: Community vs Pro

| Feature | Community | Pro |
|---------|-----------|-----|
| Attack Modules | 7 | 24 |
| HTML Reports | ✅ | ✅ |
| PDF Reports | ❌ | ✅ |
| LLM-as-Judge | ❌ | ✅ |
| Advanced Attacks | ❌ | ✅ |

### Install Pro

Pro edition is available via private repository. [Contact for access](https://calendly.com/musabdulai/guardrails-sprint)

```bash
# After obtaining access
pip install "llm-production-safety-scanner-pro @ git+ssh://git@github.com/musabdulai-io/llm-production-safety-scanner-pro.git"
```

## Features

- **7 Attack Modules** - Security, reliability, and cost vulnerability testing
- **HTML Reports** - Detailed vulnerability reports with evidence and remediation
- **CLI Interface** - Simple terminal-based scanning
- **cURL Import** - Import target configuration from cURL commands
- **Pack System** - Extensible plugin architecture for additional modules

## Tech Stack

| Category | Technology |
|----------|------------|
| **CLI** | Python, Typer, Rich |
| **Backend** | FastAPI, Uvicorn, Pydantic |
| **Reports** | Jinja2 (HTML) |
| **Packaging** | Docker, GitHub Container Registry |

## Quick Start

### Option 1: Docker (Recommended)

> **Prerequisites:** Install Docker from [docker.com/get-docker](https://docs.docker.com/get-docker/)

```bash
# Basic scan
docker run --rm ghcr.io/musabdulai-io/llm-production-safety-scanner scan https://your-app.com

# Save report to host
docker run --rm -v $(pwd)/reports:/reports ghcr.io/musabdulai-io/llm-production-safety-scanner scan https://your-app.com -o /reports/report.html
```

### Option 2: pipx

> **Prerequisites:** `pip install pipx && pipx ensurepath` (then restart terminal)

```bash
pipx run --spec git+https://github.com/musabdulai-io/llm-production-safety-scanner scanner scan https://your-app.com
```

### Option 3: uvx

> **Prerequisites:** `curl -LsSf https://astral.sh/uv/install.sh | sh`

```bash
uvx --from git+https://github.com/musabdulai-io/llm-production-safety-scanner scanner scan https://your-app.com
```

### Option 4: From Source (Poetry)

```bash
git clone https://github.com/musabdulai-io/llm-production-safety-scanner.git
cd llm-production-safety-scanner
poetry install
poetry run scanner scan https://your-app.com
```

### Option 5: From Source (pip)

```bash
git clone https://github.com/musabdulai-io/llm-production-safety-scanner.git
cd llm-production-safety-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
scanner scan https://your-app.com
```

## CLI Usage

```bash
# Basic scan
scanner scan https://your-app.com

# Fast scan (skip slow tests)
scanner scan https://your-app.com --fast

# Custom output file
scanner scan https://your-app.com --output audit.html

# With authentication header
scanner scan https://your-app.com -H "Authorization: Bearer sk-xxx"

# Import from cURL command
scanner scan --curl "curl https://api.example.com -H 'Auth: token'"

# Test competitor mentions
scanner scan https://your-app.com --competitor "Acme Corp" --competitor "BigCo"

# Don't auto-open report
scanner scan https://your-app.com --no-open

# List available packs
scanner packs

# List all attack modules
scanner attacks
```

### Commands

```
scanner scan [TARGET] [OPTIONS]    Run security scan
scanner packs                      List available attack packs
scanner attacks                    List all attack modules
scanner version                    Show version
scanner info                       Show configuration
```

### Options

| Option | Description |
|--------|-------------|
| `--output, -o` | Output file path (default: report.html) |
| `--fast, -f` | Skip slow tests |
| `--header, -H` | Custom HTTP headers |
| `--curl` | Import target from cURL command |
| `--competitor` | Competitor names to test against |
| `--concurrency, -c` | Concurrent requests (default: 5) |
| `--verbose, -v` | Include raw AI responses in report |
| `--no-open` | Don't open report in browser |
| `--test-data-dir, -d` | Directory containing custom test documents |

## Attack Modules

The Community edition includes **7 attack modules** organized into three categories:

### Security Attacks (4)

| Attack | Description |
|--------|-------------|
| **Prompt Injection** | Tests if AI can be manipulated to reveal system prompts or ignore instructions |
| **PII Leaking** | Detects exposure of emails, SSNs, API keys, credit cards |
| **Prompt Extraction** | Attempts to extract the system prompt |
| **Refusal Bypass** | Tests techniques to bypass safety refusals |

### Reliability Attacks (2)

| Attack | Description |
|--------|-------------|
| **Hallucination Detection** | Detects fabricated facts, fake citations, URLs |
| **Off-Topic Handling** | Tests refusal of harmful/off-topic requests |

### Cost Attacks (1)

| Attack | Description |
|--------|-------------|
| **Efficiency Analysis** | Measures latency and token usage |

### Pro Edition Attacks (17 additional)

The Pro edition adds 17 more advanced attack modules including:
- RAG Poisoning, Encoding Bypass, Structure Injection
- Indirect Injection, Multi-Turn Jailbreak, Language Bypass
- Many-Shot Jailbreak, Content Continuation, Tool Abuse
- Excessive Agency, Brand Safety, Competitor/Pricing Traps
- Table Parsing, Retrieval Precision, Resource Exhaustion

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   LLM Production Safety Scanner                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌───────────┐                         ┌─────────────────┐     │
│   │    CLI    │                         │   Docker CLI    │     │
│   │  (Typer)  │                         │                 │     │
│   └─────┬─────┘                         └────────┬────────┘     │
│         │                                        │               │
│         └────────────────────────────────────────┘               │
│                            │                                     │
│                            ▼                                     │
│                  ┌──────────────────┐                           │
│                  │  Scanner Service │                           │
│                  │    (FastAPI)     │                           │
│                  └────────┬─────────┘                           │
│                           │                                      │
│         ┌─────────────────┼─────────────────┐                   │
│         ▼                 ▼                 ▼                   │
│   ┌───────────┐    ┌───────────┐    ┌───────────┐             │
│   │  Attack   │    │  Pattern  │    │   Pack    │             │
│   │  Modules  │    │  Detector │    │  System   │             │
│   └─────┬─────┘    └─────┬─────┘    └─────┬─────┘             │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          ▼                                       │
│                 ┌─────────────────┐                             │
│                 │ Report Generator│                             │
│                 │     (HTML)      │                             │
│                 └─────────────────┘                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Target LLM/RAG │
                  │    Endpoint     │
                  └─────────────────┘
```

## Testing Locally

To test the scanner, you need a target RAG/LLM endpoint:

1. **Use your own target**: Any endpoint accepting POST with `{"question": "..."}`
2. **Set up a local test target**: Run a local LLM API for testing

## Development

### Prerequisites

- Python 3.11+
- Poetry (or pip)
- Docker (optional, for containerized use)

### Quick Setup

```bash
# Clone repository
git clone https://github.com/musabdulai-io/llm-production-safety-scanner.git
cd llm-production-safety-scanner

# Run setup script (installs all dependencies)
./setup.sh
```

The setup script will:
- Install Python dependencies via Poetry (or pip as fallback)
- Generate runtime environment configuration

### Run Locally

```bash
# Activate virtual environment
source .venv/bin/activate

# Run a scan
scanner scan https://your-target.com
```

### Project Structure

```
llm-production-safety-scanner/
├── backend/           # Python CLI and scanner logic
│   ├── app/          # Application code
│   └── Dockerfile    # Production container
├── samples/           # Sample audit reports
├── setup.sh          # Local setup script
└── pyproject.toml    # Python dependencies
```

## Report Format

The HTML report includes:

- **Executive Summary** - Pass/Fail status with vulnerability counts
- **Severity Breakdown** - Critical, High, Medium, Low counts
- **Attack Results** - Status and timing for each attack module
- **Vulnerability Details** - Description, evidence, and remediation for each finding

## Responsible Use

This tool is designed for **authorized security testing only**.

**Requirements:**
- You must own the system or have explicit written permission
- Only scan systems you are authorized to test
- Do not use for unauthorized access or data extraction

**Prohibited Uses:**
- Scanning systems without authorization
- Denial-of-service attacks
- Data exfiltration from production systems
- Any illegal activities

Misuse may violate computer fraud and abuse laws. See [SECURITY.md](SECURITY.md) for detailed guidelines.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `poetry run pytest`
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contact

- **Website**: [musabdulai.com](https://musabdulai.com)
- **Sample Report**: [musabdulai.com/sample-report](https://musabdulai.com/sample-report)
- **Book a Call**: [calendly.com/musabdulai](https://calendly.com/musabdulai/guardrails-sprint)
- **Email**: hello@musabdulai.com
