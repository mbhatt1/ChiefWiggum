# Quick Start: ChiefWiggum Skill

## 1. Install the Skill

From the repository root:

```bash
./SKILL_SETUP.sh
```

Or manually:

```bash
python3 -m pip install -e .
```

## 2. Verify Installation

```bash
chiefwiggum --help
```

## 3. Use the Skill in Claude Code

Claude Code automatically detects this skill. You can now use:

```
/chiefwiggum init --target-url http://localhost:8080
/chiefwiggum analyze --surface surfaces.yaml --hypothesis hyp_001.md
/chiefwiggum ledger list
/chiefwiggum report generate
```

## 4. Read the Full Guide

```bash
cat .claude/SKILL_GUIDE.md
```

## Files Added/Modified

### Created:
- `.claude/QUICK_START.md` - This file
- `.claude/SKILL_GUIDE.md` - Comprehensive skill documentation
- `SKILL_SETUP.sh` - One-command installation

### Modified:
- `.claude/skill` - Added command metadata and examples

## Key Directories

```
.claude/               # Claude Code configuration
  ├── skill           # Skill manifest (YAML frontmatter + instructions)
  ├── SKILL_GUIDE.md  # Full usage guide
  └── QUICK_START.md  # This file

src/chiefwiggum/      # Python package source
  ├── core.py         # Evidence ledger, evaluator, surface enumerator
  ├── cli.py          # CLI entry point
  ├── control.py      # 12-control standard library
  └── project.py      # Project initialization

templates/            # Skeleton files for new projects
  ├── SURFACES.yaml
  ├── HYPOTHESIS.md
  └── EVIDENCE.json
```

## Common Commands

Initialize a security audit project:
```bash
chiefwiggum init --target-url http://target.app:8000
```

Add an evidence record to the ledger:
```bash
chiefwiggum ledger add \
  --hypothesis hyp_001 \
  --result CONFIRMED \
  --evidence "PoC: ..." \
  --action PATCH \
  --patch-location src/file.py:42
```

List all findings:
```bash
chiefwiggum ledger list --filter action:PATCH
```

Generate a control map report:
```bash
chiefwiggum report generate --output report.html
```

## Need Help?

- Full documentation: `README.md`
- Advanced usage: `CHIEFWIGGUM_PLUS_PLUS.md`
- Project structure: `REPO_STRUCTURE.md`
- Skill guide: `.claude/SKILL_GUIDE.md`

## What is ChiefWiggum?

ChiefWiggum turns vulnerability discovery into **patch pipelines, not lab notebooks.**

Every hypothesis closes with an action:
- **PATCH** - Code change + regression test
- **CONTROL** - Hardening suggestion (C-001 to C-012)
- **INSTRUMENT** - Monitoring to add
- **BLOCKER** - Why it's safe (prevents re-testing)

The evidence ledger prevents you from re-testing the same hypotheses, scaling your security analysis from "did I test this?" to "what's left to fix?"

---

**Ready?** Start with: `/chiefwiggum init --target-url <your-app>`

D'oh! — ChiefWiggum++
