# ChiefWiggum Loop - Repository Structure

## Directory Layout

```
chiefwiggum-loop/
├── README.md                         ← Main documentation (START HERE)
├── CHIEFWIGGUM_PLUS_PLUS.md         ← Architecture: Actions, Controls, Evidence
├── LICENSE                           ← MIT License
├── CONTRIBUTING.md                   ← Contribution guidelines
├── CHANGELOG.md                      ← Version history
├── setup.py                          ← Package configuration
├── requirements.txt                  ← Dependencies
│
├── src/chiefwiggum/                 ← Main package (the code)
│   ├── __init__.py                  ← Exports public API
│   ├── core.py                      ← Core: Evaluator, EvidenceLedger, Hypothesis, SurfaceEnumerator
│   ├── cli.py                       ← CLI: orchestrate, ledger, report, record commands
│   ├── project.py                   ← Project initialization and loading
│   ├── control.py                   ← Control definitions (C-001 through C-012)
│   ├── hypothesis_generator.py      ← Auto-generates vulnerability hypotheses
│   └── detectors.py                 ← Multi-stage attack chain detectors
│
├── hypotheses/                       ← Hypothesis templates (20+ built-in)
│   ├── hyp_001_openwire_gadgetchain.md
│   ├── hyp_002_stomp_rce.md
│   ├── hyp_003_xml_xxe.md
│   ├── ... (17 more hypotheses)
│   └── template.md
│
├── benchmark/                        ← Evaluation benchmark
│   ├── secbench_runner.py           ← Runs 100 and 600-sample evaluations
│   ├── requirements.txt
│   ├── README.md                    ← Benchmark documentation
│   └── QUICKSTART.md
│
├── .claude/                         ← Claude Code skill integration
│   └── skills/chiefwiggum/
│       └── chiefwiggum/             ← Duplicate of src/ for skill
│
└── [other files]
    ├── tests/                       ← Test suite (to be created)
    └── examples/                    ← Example projects (to be created)
```

## Key Files Explained

### Core Documentation

**README.md** (READ FIRST)
- Project overview
- Quick start: `chiefwiggum orchestrate --target-url ... --codebase-path ...`
- Feature overview
- Installation and usage
- Control map report explanation
- Python and CLI API

**CHIEFWIGGUM_PLUS_PLUS.md**
- Architecture of the framework
- ActionType requirement (PATCH | CONTROL | INSTRUMENT | BLOCKER)
- 12-control standard library (C-001 to C-012)
- Evidence schema design
- Example: Shell injection → Control → Patch
- Ralphization checklist

### Source Code

**src/chiefwiggum/core.py**
- `Evidence` — Single piece of evidence about a vulnerability
- `EvidenceLedger` — Persistent memory of tested hypotheses
- `Hypothesis` — A testable claim about a vulnerability
- `Evaluator` — Main testing harness
- `SurfaceEnumerator` — Identifies dangerous functions

**src/chiefwiggum/cli.py**
- `orchestrate` — End-to-end testing loop (1/5 phases)
- `ledger list` — View evidence ledger
- `report generate` — Generate hardening backlog
- `record` — Record hypothesis result

**src/chiefwiggum/control.py**
- `ControlCategory` enum
- `StandardControl` definitions
- 12 controls: C-001 through C-012
- Control metadata and descriptions

**src/chiefwiggum/hypothesis_generator.py**
- `generate_hypotheses()` — Creates 20+ hypothesis templates
- Covers: injection, deserialization, XXE, auth, input validation
- Based on HYPOTHESIS_TEMPLATES list

**src/chiefwiggum/detectors.py**
- `AttackChainDetector` — Detects multi-stage vulnerability chains
- `detect_protocol_injection_in_broker_config()` — Generic protocol injection detector
- Framework for sophisticated attack detection

**src/chiefwiggum/project.py**
- `create_project()` — Initialize new project
- `load_project()` — Load existing project
- `get_project_info()` — Return project metadata
- `init_in_place()` — Initialize in current directory
- `init_from_url()` — Clone repo and initialize

### Hypothesis Templates

**hypotheses/** — 20+ built-in hypotheses covering:

Deserialization:
- `hyp_001_openwire_gadgetchain.md` — ClassPathXmlApplicationContext gadget
- `hyp_002_stomp_rce.md` — STOMP protocol serialization
- `hyp_005_amqp_unmarshalling.md` — AMQP type decoder gadgets

RCE:
- `hyp_004_spel_injection.md` — Spring Expression Language
- `hyp_007_plugin_classloader.md` — Arbitrary class loading
- `hyp_010_jndi_injection.md` — JNDI injection
- `hyp_011_groovy_script.md` — Groovy script execution
- `hyp_012_velocity_template.md` — Velocity template injection
- `hyp_014_expression_language.md` — Expression language evaluation
- `hyp_018_script_engine.md` — JavaScript script engine
- `hyp_019_bean_property_injection.md` — Spring bean property injection
- `hyp_020_method_invocation.md` — Unsafe method invocation

XXE/Config:
- `hyp_003_xml_xxe.md` — XXE entity expansion
- `hyp_013_java_properties.md` — Java properties injection
- `hyp_015_json_deserialization.md` — JSON deserialization
- `hyp_016_jar_loading.md` — JAR file loading
- `hyp_017_reflection_gadget.md` — Reflection gadget chains

Injection:
- `hyp_006_ldap_injection.md` — LDAP filter injection
- `hyp_008_path_traversal.md` — Path traversal attacks
- `hyp_009_mqtt_wildcard_dos.md` — MQTT ReDoS

### Benchmark

**benchmark/secbench_runner.py**
- Runs 100 and 600-sample vulnerability evaluations
- Compares: Pattern matching vs LLM-based detection
- Metrics: ROC-AUC, accuracy, recall, precision, F1
- Generates analysis reports and visualizations

**benchmark/README.md**
- Benchmark documentation
- How to run evaluations
- Interpretation of results

## Project Initialization Structure

When you run `chiefwiggum orchestrate`, it creates:

```
project_root/
├── ground_truth/
│   └── TARGET.md                     ← Target asset & threat model
├── surfaces/
│   └── SURFACES.yaml                 ← Attack surfaces
├── hypotheses/
│   ├── hyp_001.md
│   ├── hyp_002.md
│   └── ... (auto-generated)
└── evidence/
    ├── confirmed/
    │   └── *.json                    ✓ Confirmed vulnerabilities
    ├── disproven/
    │   └── *.json                    ✗ Already tested, safe
    └── unclear/
        └── *.json                    ? Needs instrumentation
```

## Key Design Decisions

### 1. Evidence Ledger Pattern
Instead of re-testing hypotheses, maintain a persistent ledger:
- `evidence/confirmed/` — Tested and found vulnerable
- `evidence/disproven/` — Tested and found safe
- `evidence/unclear/` — Tested but inconclusive

### 2. Action Type Requirement (ChiefWiggum++)
Every evidence entry MUST have an action:
- `PATCH` — Fix the code (patch_location required)
- `CONTROL` — Apply hardening control (control_id required)
- `INSTRUMENT` — Add instrumentation/logging (instrumentation required)
- `BLOCKER` — Safe (blocking_reason required)

### 3. 12-Control Standard Library
Reusable hardening controls instead of inventing new fixes:
- **C-001 to C-012** map to common security patterns
- Each control is documented with implementation examples
- Hypothesis validation maps to appropriate control

### 4. Hypothesis Templates
Pre-built hypotheses covering 100+ vulnerability patterns:
- Auto-generated from templates
- Can be customized or extended
- Each template includes reachability, sink, and control

## Development

### Adding a New Command

1. Add function in `src/chiefwiggum/cli.py` decorated with `@main.command()`
2. Add options with `@click.option()`
3. Implement command logic
4. Test with `pytest tests/test_cli.py`

### Adding a New Attack Chain Detector

1. Add method to `AttackChainDetector` in `src/chiefwiggum/detectors.py`
2. Call from `detect_all()` method
3. Return list of findings with proper structure
4. Test with real codebase

### Adding a New Control

1. Add to `STANDARD_CONTROLS` dict in `src/chiefwiggum/control.py`
2. Define control metadata (name, description, mitigation)
3. Reference in hypothesis templates

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=chiefwiggum tests/

# Run specific test file
pytest tests/test_core.py -v
```

## Build and Deploy

```bash
# Install in development mode
pip install -e .

# Build distribution
python setup.py sdist bdist_wheel

# Upload to PyPI (when ready)
twine upload dist/*
```

---

**D'oh!** — Structured security testing through persistent memory and actionable evidence.
