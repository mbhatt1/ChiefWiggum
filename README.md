# ChiefWiggum Loop

**D'oh! I found it!** — A structured vulnerability testing framework with persistent memory.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)

## What Is It?

ChiefWiggum Loop is a framework for structured security vulnerability analysis that uses persistent evidence ledgers to avoid re-testing hypotheses.

**The problem:** Security testing wastes time re-analyzing the same code and re-testing the same hypotheses.

**The solution:** Record evidence (confirmed, disproven, or unclear) in a ledger that persists across analysis iterations.

## Quick Start

```bash
# Run end-to-end vulnerability analysis with orchestration
chiefwiggum orchestrate \
  --target-url "https://github.com/<repo>" \
  --codebase-path "/tmp/<repo>" \
  --validate

# Output:
# ✓ Found 20+ hypotheses
# ✓ Validated against codebase
# ✓ Generated hardening backlog (patches, controls, instrumentation)
```

## The Orchestration Loop

The `orchestrate` command runs a complete vulnerability testing cycle:

```
1. Initialize     → Create project structure (ground_truth/, hypotheses/, evidence/)
2. Enumerate      → Identify attack surfaces from codebase
3. Hypothesize    → Generate vulnerability hypotheses
4. Validate       → Test hypotheses against target codebase
5. Report         → Generate prioritized hardening backlog
```

## What Gets Generated

After orchestration, you have:

```
project/
├── ground_truth/
│   └── TARGET.md                 ← Target asset & threat model
├── surfaces/
│   └── SURFACES.yaml             ← Attack surfaces (entry → sink)
├── hypotheses/
│   ├── hyp_001_openwire_gadgetchain.md
│   ├── hyp_002_stomp_rce.md
│   └── ... (20+ hypotheses)
└── evidence/
    ├── confirmed/
    │   └── hyp_001.json          ✓ Confirmed vulnerabilities
    ├── disproven/
    │   └── hyp_005.json          ✗ Already tested, safe
    └── unclear/
        └── hyp_003.json          ? Needs instrumentation
```

## Key Features

✅ **Evidence Ledger** — Never re-test the same hypothesis
✅ **Control Map Report** — Prioritized hardening backlog
✅ **Multi-Stage Attack Detection** — Catch complex vulnerability chains
✅ **Codebase Validation** — Test hypotheses against real code
✅ **Reusable Format** — Machine-parseable YAML/JSON output

## Installation

```bash
# From source
git clone https://github.com/mbhatt1/ChiefWiggum
cd ChiefWiggum
pip install -e .

# Or from PyPI (when published)
pip install chiefwiggum-loop
```

## Command Line Usage

### Initialize a New Project

```bash
chiefwiggum init --target-url "https://github.com/yourorg/yourapp"
```

Creates project structure and seed hypotheses.

### Run Complete Analysis (Recommended)

```bash
chiefwiggum orchestrate \
  --target-url "https://github.com/yourorg/yourapp" \
  --codebase-path /path/to/source \
  --validate
```

Runs all 5 phases and generates a hardening backlog.

### View Evidence Ledger

```bash
chiefwiggum ledger list

# Output:
# ✓ Confirmed:  15
# ✗ Disproven:   3
# ? Unclear:     2
```

### Generate Reports

```bash
chiefwiggum report generate --format text
chiefwiggum report generate --format json
```

Outputs hardening backlog grouped by:
- **PATCHES READY** — Confirmed vulnerabilities needing code fixes
- **CONTROLS NEEDED** — Confirmed vulnerabilities needing hardening controls
- **INSTRUMENTATION NEEDED** — Unclear results needing more data

### Record a Hypothesis Result

```bash
chiefwiggum record hyp_001 \
  --confirmed \
  --location "src/RCE.java:123" \
  --description "ClassPathXmlApplicationContext gadget chain confirmed" \
  --action PATCH \
  --patch-location "org/apache/codebase/openwire/v12/BaseDataStreamMarshaller.java"
```

## Project Structure

```
chiefwiggum-loop/
├── src/chiefwiggum/
│   ├── core.py              ← EvidenceLedger, Evaluator, Hypothesis
│   ├── cli.py               ← Command-line interface (orchestrate, ledger, report)
│   ├── project.py           ← Project initialization & loading
│   ├── detectors.py         ← Attack chain detectors
│   ├── control.py           ← C-001 to C-012 control definitions
│   └── hypothesis_generator.py ← Hypothesis template generation
├── benchmark/
│   ├── secbench_runner.py   ← Evaluation benchmark for testing
│   └── README.md
├── hypotheses/
│   ├── hyp_*.md             ← Hypothesis templates (20+ patterns)
│   └── template.md
├── README.md                ← This file
└── setup.py
```

## Core Components

### EvidenceLedger

Persistent memory of tested hypotheses:

```python
from chiefwiggum import EvidenceLedger, EvidenceType, ActionType

ledger = EvidenceLedger(project_root)

# Record a confirmed vulnerability
ledger.add_evidence(
    hypothesis_id="hyp_001_openwire_gadgetchain",
    evidence_type=EvidenceType.CONFIRMED,
    code_location="BaseDataStreamMarshaller.java:310",
    description="ClassPathXmlApplicationContext gadget chain present",
    action=ActionType.PATCH,
    patch_location="BaseDataStreamMarshaller.java:createThrowable()"
)

# Check if already tested
if ledger.has_been_tested("hyp_002"):
    print("Skip: already tested")

# List all confirmed
for evidence in ledger.list_confirmed():
    print(f"{evidence.hypothesis_id}: {evidence.code_location}")
```

### Evaluator

Main testing harness for evaluating hypotheses:

```python
from chiefwiggum import Evaluator, EvidenceType, ActionType

evaluator = Evaluator(project_root)

# Test a hypothesis
evaluator.ledger.add_evidence(
    hypothesis_id="hyp_003_xml_xxe",
    evidence_type=EvidenceType.CONFIRMED,
    code_location="XMLParser.java:45",
    description="XXE entity expansion enabled",
    action=ActionType.CONTROL,
    control_id="C-006"
)

# Get summary
summary = evaluator.get_summary()
print(f"Confirmed: {summary['confirmed']}/20")

# Generate control map report
print(evaluator.control_map_report())
```

### SurfaceEnumerator

Identify dangerous functions in codebase:

```python
from chiefwiggum import SurfaceEnumerator

enumerator = SurfaceEnumerator(source_root)
surfaces = enumerator.enumerate()

# Returns list of dangerous functions
# (sinks like Runtime.exec, ObjectInputStream, etc.)
```

## Control Map Report

The `orchestrate` command generates a prioritized hardening backlog:

```
PATCHES READY (19 items) ← Start here for quick wins
  [hyp_001_openwire_gadgetchain] OpenWire gadget chain RCE
    Location: BaseDataStreamMarshaller.java:createThrowable()
    Test: testOpenWireRejectsClassPathXmlApplicationContext
    Status: ✓ CONFIRMED

CONTROLS NEEDED (1 item) ← Deploy these hardening controls
  [hyp_003_xml_xxe] XXE entity expansion in XML parser
    Control: C-006 (Disable XXE)
    Status: ✓ CONFIRMED, needs C-006

INSTRUMENTATION NEEDED (0 items) ← Add logging to resolve
BLOCKERS / SAFE SURFACES (0 items) ← Safe (no action needed)
```

## Hypothesis Templates

The framework includes 20+ built-in hypothesis templates covering:

- Deserialization gadget chains (ClassPathXmlApplicationContext, ROME, commons-collections)
- RCE vectors (OpenWire, STOMP, AMQP, SpEL injection)
- XXE vulnerabilities (DTD expansion, SSRF)
- LDAP injection (authentication bypass)
- Path traversal attacks
- DoS attacks (ReDoS, resource exhaustion)

Hypotheses are stored in `hypotheses/` and automatically validated during orchestration.

## Control Library (C-001 to C-012)

Standard hardening controls referenced in reports:

- **C-001:** Shell Execution Wrapper (no raw system/popen)
- **C-002:** Argument Allowlist + No Shell Parsing
- **C-003:** Path Canonicalization + Allowlist
- **C-004:** Zip/Tar Safe Extract (no symlinks, size limits)
- **C-005:** YAML Safe Loader Only
- **C-006:** XML External Entities (XXE) Disabled
- **C-007:** Deserialization Allowlist/Ban
- **C-008:** SSRF Outbound Allowlist + DNS Pinning
- **C-009:** Template Rendering Sandboxing
- **C-010:** Rate Limits + Payload Size Caps
- **C-011:** Privilege Drop + Sandbox Around Risky Ops
- **C-012:** Audit Logging on Trust Boundaries

## Examples

Complete examples with actual codebase analysis:

```bash
# Run on Apache codebase
chiefwiggum orchestrate \
  --target-url "https://github.com/code/codebase" \
  --codebase-path /path/to/codebase \
  --validate

# Output shows:
# ✓ Found 20 hypotheses
# ✓ Confirmed 19 vulnerabilities
# ✓ Generated patches ready: OpenWire RCE, STOMP RCE, AMQP RCE, SpEL injection...
```

## Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=chiefwiggum tests/

# Run integration tests
pytest tests/integration/
```

## Contributing

Contributions welcome! Please:

1. Fork the repo
2. Create a feature branch
3. Commit changes
4. Push to branch
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT License — see [LICENSE](LICENSE) file for details.

## Citation

If you use ChiefWiggum Loop in your security research:

```bibtex
@software{chiefwiggum2026,
  title={ChiefWiggum: Security Vulnerability Testing Framework},
  author={mbhatt1},
  year={2026},
  url={https://github.com/mbhatt1/ChiefWiggum}
}
```

## References

- **Ralph Loop:** OpenAI evals methodology
- **SEC-bench:** Vulnerability evaluation dataset
- **OWASP:** Top 10 vulnerability categories

## Contact

- Issues: [GitHub Issues](https://github.com/mbhatt1/ChiefWiggum/issues)
- Discussions: [GitHub Discussions](https://github.com/mbhatt1/ChiefWiggum/discussions)

---

**D'oh!** — ChiefWiggum Loop: Because infinite security testing loops are for donuts, not production code.
