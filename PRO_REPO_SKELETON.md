# Pro Repository Skeleton Specification

This document specifies how to set up the `ai-security-scanner-pro` private repository.

## Directory Structure

```
ai-security-scanner-pro/
├── pyproject.toml
├── README.md
├── LICENSE                     # Commercial license
├── scanner_pro/
│   ├── __init__.py
│   └── packs/
│       ├── __init__.py
│       ├── pro_security.py     # 11 security attacks
│       ├── pro_reliability.py  # 4 reliability attacks
│       ├── pro_cost.py         # 1 cost attack
│       ├── llm_judge.py        # LLM-as-Judge pack
│       └── pdf_reports.py      # PDF report generation
└── tests/
    └── test_pro_packs.py
```

## pyproject.toml

```toml
[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"

[tool.poetry]
name = "ai-security-scanner-pro"
version = "1.0.0"
description = "Pro attack packs for AI Security Scanner"
authors = ["Musa Abdulai"]
packages = [{include = "scanner_pro"}]

[tool.poetry.dependencies]
python = "^3.11"
ai-security-scanner = "^1.0.0"  # Depends on community
weasyprint = "^62.0"            # For PDF generation
openai = "^1.0.0"               # For LLM Judge
anthropic = "^0.20.0"           # For LLM Judge

[tool.poetry.plugins."ai_security_scanner.packs"]
pro-security = "scanner_pro.packs.pro_security:ProSecurityPack"
pro-reliability = "scanner_pro.packs.pro_reliability:ProReliabilityPack"
pro-cost = "scanner_pro.packs.pro_cost:ProCostPack"
llm-judge = "scanner_pro.packs.llm_judge:LLMJudgePack"
pdf-reports = "scanner_pro.packs.pdf_reports:PDFReportsPack"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0.0"
pytest-asyncio = "^0.23.0"
```

## Pro Attack Modules to Include

### Security Attacks (11)

Move these from the Community repo:

| File | Class |
|------|-------|
| `security/encoding_attacks.py` | `EncodingAttack` |
| `security/indirect_injection.py` | `IndirectInjection` |
| `security/rag_poisoning.py` | `RAGPoisoner` |
| `security/tool_abuse.py` | `ToolAbuseAttack` |
| `security/excessive_agency.py` | `ExcessiveAgency` |
| `security/multi_turn_attacks.py` | `MultiTurnAttack` |
| `security/language_attacks.py` | `LanguageAttack` |
| `security/many_shot_jailbreak.py` | `ManyShotJailbreak` |
| `security/content_continuation.py` | `ContentContinuationAttack` |
| `security/structure_attacks.py` | `StructureAttack` |
| `security/output_weaponization.py` | `OutputWeaponization` |

### Reliability Attacks (4)

| File | Class |
|------|-------|
| `reliability/brand_safety.py` | `BrandSafetyTest` |
| `reliability/retrieval_precision.py` | `RetrievalPrecisionTest` |
| `reliability/table_parsing.py` | `TableParsingTest` |
| `reliability/reliability_checks.py` | `CompetitorTrap`, `PricingTrap` |

### Cost Attacks (1)

| File | Class |
|------|-------|
| `cost/resource_exhaustion.py` | `ResourceExhaustionAttack` |

### Core Components

| File | Reason |
|------|--------|
| `backend/app/core/judge.py` | LLM-as-Judge functionality |
| `backend/app/features/scanner/reporting/pdf.py` | PDF report generation |

## Example Pack Implementation

### scanner_pro/packs/pro_security.py

```python
from typing import List

from backend.app.features.scanner.attacks.base import AttackModule
from backend.app.features.scanner.packs.protocol import Pack, PackMetadata, PackTier

# Import Pro attack modules (copied to this repo)
from scanner_pro.attacks.security.encoding_attacks import EncodingAttack
from scanner_pro.attacks.security.indirect_injection import IndirectInjection
from scanner_pro.attacks.security.rag_poisoning import RAGPoisoner
from scanner_pro.attacks.security.tool_abuse import ToolAbuseAttack
from scanner_pro.attacks.security.excessive_agency import ExcessiveAgency
from scanner_pro.attacks.security.multi_turn_attacks import MultiTurnAttack
from scanner_pro.attacks.security.language_attacks import LanguageAttack
from scanner_pro.attacks.security.many_shot_jailbreak import ManyShotJailbreak
from scanner_pro.attacks.security.content_continuation import ContentContinuationAttack
from scanner_pro.attacks.security.structure_attacks import StructureAttack
from scanner_pro.attacks.security.output_weaponization import OutputWeaponization


class ProSecurityPack(Pack):
    """Pro security attacks with advanced techniques."""

    @property
    def metadata(self) -> PackMetadata:
        return PackMetadata(
            name="pro-security",
            version="1.0.0",
            tier=PackTier.PRO,
            description="Advanced security attacks including RAG poisoning, encoding bypass, and multi-turn jailbreaks",
        )

    def get_attack_modules(self, **kwargs) -> List[AttackModule]:
        return [
            EncodingAttack(),
            IndirectInjection(),
            RAGPoisoner(),
            ToolAbuseAttack(),
            ExcessiveAgency(),
            MultiTurnAttack(),
            LanguageAttack(),
            ManyShotJailbreak(),
            ContentContinuationAttack(),
            StructureAttack(),
            OutputWeaponization(),
        ]
```

## Installation Commands

### Development (Editable Install)

```bash
# Install community edition first
cd ai-security-scanner
pip install -e .

# Then install pro edition
cd ../ai-security-scanner-pro
pip install -e .
```

### Production (From Private Repo)

```bash
# Via SSH
pip install "ai-security-scanner-pro @ git+ssh://git@github.com/musabdulai-io/ai-security-scanner-pro.git"

# Via HTTPS with token
pip install "ai-security-scanner-pro @ git+https://${GITHUB_TOKEN}@github.com/musabdulai-io/ai-security-scanner-pro.git"
```

## Verification

After installing Pro, verify it works:

```bash
# List packs (should show community + pro packs)
scanner packs

# List attacks (should show all 24 attacks)
scanner attacks

# Run scan with pro (should include all attacks)
scanner scan https://your-target.com
```

## Git Filter-Repo Commands

To remove Pro code from public repo history after migration:

```bash
# 1. BACKUP FIRST - create mirror clone
git clone --mirror git@github.com:musabdulai-io/ai-security-scanner.git ai-security-scanner-backup.git

# 2. Clone fresh for rewrite
git clone git@github.com:musabdulai-io/ai-security-scanner.git ai-security-scanner-rewrite
cd ai-security-scanner-rewrite

# 3. Remove Pro paths from history
git filter-repo --invert-paths \
  --path backend/app/features/scanner/attacks/security/indirect_injection.py \
  --path backend/app/features/scanner/attacks/security/rag_poisoning.py \
  --path backend/app/features/scanner/attacks/security/tool_abuse.py \
  --path backend/app/features/scanner/attacks/security/excessive_agency.py \
  --path backend/app/features/scanner/attacks/security/multi_turn_attacks.py \
  --path backend/app/features/scanner/attacks/security/language_attacks.py \
  --path backend/app/features/scanner/attacks/security/many_shot_jailbreak.py \
  --path backend/app/features/scanner/attacks/security/content_continuation.py \
  --path backend/app/features/scanner/attacks/security/structure_attacks.py \
  --path backend/app/features/scanner/attacks/security/encoding_attacks.py \
  --path backend/app/features/scanner/attacks/security/output_weaponization.py \
  --path backend/app/features/scanner/attacks/reliability/retrieval_precision.py \
  --path backend/app/features/scanner/attacks/reliability/table_parsing.py \
  --path backend/app/features/scanner/attacks/reliability/brand_safety.py \
  --path backend/app/features/scanner/attacks/cost/resource_exhaustion.py \
  --path backend/app/features/scanner/reporting/pdf.py \
  --path backend/app/core/judge.py \
  --path-glob '**/__pycache__/**' \
  --path-glob '**/*.pyc'

# 4. Re-add remote (filter-repo removes it)
git remote add origin git@github.com:musabdulai-io/ai-security-scanner.git

# 5. Force push all branches and tags
git push --force --all origin
git push --force --tags origin
```

## Safety Checklist Before History Rewrite

- [ ] Create mirror backup: `git clone --mirror`
- [ ] Save list of all tags: `git tag -l > tags.txt`
- [ ] Notify any collaborators (check fork count)
- [ ] Verify no open PRs
- [ ] Run `gitleaks detect` on backup to check for secrets
- [ ] If secrets found, rotate those credentials
- [ ] After force-push, verify new clones don't contain Pro code
- [ ] All existing clones must be deleted and re-cloned
