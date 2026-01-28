# ChiefWiggum Loop - Repository Structure

## Directory Layout

```
chiefwiggum-loop/
├── README.md                    ← Main documentation
├── LICENSE                      ← MIT License
├── CONTRIBUTING.md              ← Contribution guidelines
├── CHANGELOG.md                 ← Version history
├── setup.py                     ← Package configuration
├── requirements.txt             ← Dependencies
├── .gitignore                   ← Git ignore patterns
│
├── src/chiefwiggum/             ← Main package
│   ├── __init__.py              ← Package init (exports API)
│   ├── core.py                  ← Core classes (Evaluator, EvidenceLedger, etc.)
│   ├── project.py               ← Project management
│   └── cli.py                   ← Command-line interface
│
├── examples/                    ← Example projects (not yet created)
│   ├── file_upload_rce/
│   ├── config_injection/
│   └── deserialize_gadget/
│
├── tests/                       ← Test suite (not yet created)
│   ├── test_core.py
│   ├── test_project.py
│   └── test_cli.py
│
└── docs/                        ← Documentation (not yet created)
    ├── QUICKSTART.md
    ├── METHODOLOGY.md
    ├── API.md
    └── EVALUATION.md
```

## Key Files

### Root Level

**README.md**
- Overview of project
- Quick start example
- Key results and metrics
- Installation instructions
- Usage examples
- Comparison with other tools

**LICENSE**
- MIT License
- Permissive open-source license

**setup.py**
- Package metadata
- Dependencies
- Entry points (CLI commands)
- Classifiers and keywords

**requirements.txt**
- Core dependencies (PyYAML, click, tabulate, dataclasses-json)
- Development dependencies (pytest, black, flake8, mypy)

**CONTRIBUTING.md**
- Development setup
- Code style guidelines
- Testing procedures
- PR submission process

**CHANGELOG.md**
- Version history
- What changed in each release
- Semantic versioning info
- Roadmap

### Source Code

**src/chiefwiggum/__init__.py**
- Package initialization
- Exports public API
- Version string

**src/chiefwiggum/core.py** (~250 lines)
- `Evidence` dataclass
- `Hypothesis` dataclass
- `EvidenceType` enum
- `EvidenceLedger` class (main innovation)
- `SurfaceEnumerator` class
- `Evaluator` class (main harness)

**src/chiefwiggum/project.py** (~80 lines)
- `create_project()` function
- `load_project()` function
- `get_project_info()` function
- Project initialization logic

**src/chiefwiggum/cli.py** (~200 lines)
- CLI group and commands
- `init` — Create new project
- `info` — Show project info
- `evidence` — Show evidence ledger
- `report` — Generate report
- `record` — Record test result
- `check` — Check status

## How to Use

### 1. Installation

```bash
# From GitHub (when available)
pip install chiefwiggum-loop

# Or from source
git clone https://github.com/yourusername/chiefwiggum-loop
cd chiefwiggum-loop
pip install -e .
```

### 2. Create a Project

```bash
chiefwiggum init my_security_audit
cd my_security_audit
```

This creates:
```
my_security_audit/
├── chiefwiggum.json
├── ground_truth/TARGET.md
├── surfaces/SURFACES.yaml
├── hypotheses/
├── pocs/
└── evidence/
    ├── confirmed/
    ├── disproven/
    └── unclear/
```

### 3. Define Your Target

Edit `ground_truth/TARGET.md`:
```markdown
# Target: MyApp v1.0

## Asset
Name: File upload handler
Version: 1.0.0

## Threat Model
Attacker: Unauthenticated network user
Goal: Remote code execution
Entry: POST /api/upload
```

### 4. Enumerate Surfaces

Edit `surfaces/SURFACES.yaml`:
```yaml
surfaces:
  - id: upload_shell_injection
    entry: POST /api/upload (multipart filename)
    chain:
      - step: Extract filename
        location: upload.c:45
      - step: Pass to popen()
        location: unzip.c:92
    status: untested
```

### 5. Test Hypothesis

Create `hypotheses/hyp_001.md`:
```markdown
# Hypothesis 1: Shell Injection

Claim: Filename with backticks executes commands
Path: POST /upload → filename extraction → popen()
Proof: Command output in response
```

### 6. Record Evidence

```bash
chiefwiggum record hyp_001 \
  --confirmed \
  --location "unzip.c:92" \
  --description "NULL pointer dereference at popen()"
```

Or manually:
```bash
cat > evidence/confirmed/hyp_001.md << 'EOF'
# Evidence: Upload RCE

Status: ✓ CONFIRMED
Sink: unzip.c:92
Proof: Command executed (`id` output in response)
EOF
```

### 7. View Results

```bash
chiefwiggum evidence
chiefwiggum report
```

## Package Contents

### Core Classes

**`Evaluator`** (main testing harness)
- `test_hypothesis(id, confirmed, location, description)`
- `skip_hypothesis(id)` — Check if already tested
- `get_summary()` — Statistics
- `report()` — Generate report

**`EvidenceLedger`** (persistent memory)
- `add_evidence(hyp_id, type, location, description)`
- `has_been_tested(hyp_id)` — Check ledger
- `was_confirmed(hyp_id)`
- `was_disproven(hyp_id)`
- `list_confirmed()`, `list_disproven()`, `list_unclear()`
- `summary()` — Statistics

**`SurfaceEnumerator`** (reachability)
- `find_dangerous_functions()` — Known sinks
- `enumerate()` — Find attack surfaces

### CLI Commands

| Command | Purpose |
|---------|---------|
| `chiefwiggum init NAME` | Create project |
| `chiefwiggum info` | Show project metadata |
| `chiefwiggum evidence` | Show evidence ledger |
| `chiefwiggum report` | Generate report |
| `chiefwiggum record ID` | Record test result |
| `chiefwiggum check` | Check ledger status |

## Dependencies

### Core
- **PyYAML** — Parse SURFACES.yaml
- **click** — CLI framework
- **tabulate** — Format tables
- **dataclasses-json** — Serialize/deserialize

### Development
- **pytest** — Unit testing
- **pytest-cov** — Coverage reports
- **black** — Code formatting
- **flake8** — Linting
- **mypy** — Type checking

## Development Workflow

### Setup

```bash
git clone https://github.com/yourusername/chiefwiggum-loop
cd chiefwiggum-loop
pip install -e ".[dev]"
```

### Code Style

```bash
black src/ tests/
flake8 src/ tests/
mypy src/
```

### Testing

```bash
pytest tests/
pytest --cov=chiefwiggum tests/
```

### Making a PR

1. Create branch: `git checkout -b feature/X`
2. Make changes
3. Test: `pytest`
4. Format: `black src/`
5. Lint: `flake8 src/`
6. Commit: `git commit -m "feat: Add X"`
7. Push: `git push origin feature/X`
8. Create PR on GitHub

## Next Steps

### To Add

1. **Examples/** — Complete worked examples
2. **Tests/** — Comprehensive test suite
3. **Docs/** — Full documentation
4. **Integration** — Static analysis tool integration
5. **Web UI** — Visualization dashboard

### To Improve

1. Better surface enumeration (parse source code)
2. Automated entry point discovery
3. Patch validation framework
4. Multi-team collaboration
5. CVE/CWE database integration

## References

- **Ralph Loop** (OpenAI Evals)
- **Go-Explore** (cell archives)
- **Threat Modeling** (Shostack)
- **SEC-bench** Dataset (600 vulnerabilities)

## License

MIT License — see LICENSE file

---

**D'oh!** — ChiefWiggum Loop
Because infinite loops are for donuts, not security testing.
