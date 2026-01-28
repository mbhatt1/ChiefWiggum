# ChiefWiggum++

**The Upgrade: From Lab Notebook to Patch Pipeline**

D'oh! I found it — and here's exactly how to fix it.

---

## What Changed

Original ChiefWiggum was an evidence ledger (good for preventing re-testing). **ChiefWiggum++ turns it into a Ralph-effective patch pipeline.**

**Key principle:** Every hypothesis closes with exactly one actionable output.

```
BEFORE (ChiefWiggum):
  hyp_001 → PoC → Evidence ledger: "confirmed, null pointer at file.c:310"

AFTER (ChiefWiggum++):
  hyp_001 → PoC → Evidence ledger: "confirmed, null pointer at file.c:310"
                → Action: "PATCH: Replace C-001 control in src/file.c:310"
                → Control file: controls/C-001_shell_exec_guard.md
                → Patch ready: patches/P-001_safe_exec_wrapper/
```

---

## The 4 Key Additions

### 1. **ActionType Requirement** (The Gate)

Every evidence entry MUST have one of these actions:

```python
class ActionType(Enum):
    PATCH       # Confirmed + ready to code
    CONTROL     # Confirmed + needs hardening (control library)
    INSTRUMENT  # Unclear + needs instrumentation (add logging/tracing)
    BLOCKER     # Disproven + documents why it's safe
```

**No evidence entry can be empty.** If you can't decide the action, the hypothesis isn't done.

### 2. **12-Control Standard Library** (The Reusable Building Blocks)

Instead of inventing new fixes every time, we have a proven control library:

```
C-001: Shell Execution Wrapper
C-002: Argument Allowlist + No Shell Parsing
C-003: Path Canonicalization + Allowlist
C-004: Zip/Tar Safe Extract
C-005: YAML Safe Loader Only
C-006: XML External Entities (XXE) Disabled
C-007: Deserialization Allowlist/Ban
C-008: SSRF Outbound Allowlist + DNS Pinning
C-009: Template Rendering Sandboxing
C-010: Rate Limits + Payload Size Caps
C-011: Privilege Drop + Sandbox Around Risky Ops
C-012: Audit Logging on Trust Boundaries
```

Every vulnerability maps to one or more of these. No NIH (Not Invented Here).

### 3. **Ralph Metadata in SURFACES.yaml** (The Hardening Backlog)

SURFACES.yaml now includes these fields for each surface:

```yaml
surfaces:
  - id: upload_shell_injection
    name: "..."

    # Ralph Metadata (ChiefWiggum++):
    entrypoint: "POST /api/upload (multipart filename)"
    sink: "popen(unzip -d /tmp + filename)"
    data_transformations:
      - "multipart parsing (decode)"
      - "filename extraction (NO NORMALIZATION)"
      - "string concatenation"
      - "shell interpretation"

    trust_boundary: "untrusted (HTTP) → privileged (extraction)"
    recommended_control: "C-001"  # Shell Execution Wrapper
    default_fix: "replace popen() with safe_exec(argv)"
```

This transforms discovery into a **prioritized hardening backlog automatically.**

### 4. **Control Map Report** (Ralph-Style Output)

Run `evaluator.control_map_report()` and get:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATCHES READY (3 items) ← Start here
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[hyp_001] Shell injection in unzip
  Location: src/unzip.c:92
  Test: test_shell_injection_blocked()

[hyp_002] Config variable expansion RCE
  Location: src/config.c:260
  Test: test_config_safe_exec()

[hyp_008] YAML deserialization RCE
  Location: src/parse.py:50
  Test: test_yaml_safe_load()

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTROLS NEEDED (2 items) ← Deploy these
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[hyp_003] Path traversal in ZIP
  Control: C-003 (Path Canonicalization + Allowlist)

[hyp_005] Symlink following
  Control: C-004 (Zip/Tar Safe Extract)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INSTRUMENTATION NEEDED (1 item) ← Add tracing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[hyp_007] Race condition timing
  Missing: Microsecond-accurate timestamp logs
  Status: UNCLEAR until above data available

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BLOCKERS / SAFE SURFACES (4 items) ← Already safe
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[hyp_004] Buffer overflow in parser
  Reason: Input validated against 512-byte max, buffer is 1024
```

**This is why Ralph feels effective.** You can see your hardening progress.

---

## The 15-Minute Ralphization Checklist

When you write a hypothesis, it MUST include these 5 lines (takes ~15 min):

```markdown
# REACHABILITY
HTTP POST /api/upload → multipart → filename extraction → unzip.c:92 → popen()

# SINK
popen("unzip -d /tmp " + filename) at src/unzip.c:92

# CONTROL
C-001: Shell Execution Wrapper (replace all popen/system/spawn)

# PATCH
src/unzip.c:92 - Replace popen(cmd_string) with safe_exec(argv_array)

# TEST
test_shell_injection_blocked() - Fuzz with `id`, $(whoami), $((1+1)), etc.
```

**If you can't fill these 5 lines, the hypothesis isn't ready.**

---

## New Folder Structure

```
my_security_audit/
├── ground_truth/
│   └── TARGET.md                  ← What are we testing?

├── surfaces/
│   └── SURFACES.yaml              ← Ralph metadata included

├── hypotheses/
│   ├── hyp_001.md                 ← Includes Ralphization checklist
│   └── hyp_002.md

├── controls/                       ← NEW: Reusable hardening
│   ├── C-001_shell_exec_guard.md
│   ├── C-003_path_allowlist.md
│   └── C-005_yaml_safe_load.md

├── patches/                        ← NEW: PR-ready diffs
│   ├── P-001_safe_exec_wrapper/
│   │   ├── patch.diff
│   │   └── test_regression.py
│   └── P-003_path_validation/
│       ├── patch.diff
│       └── test_traverse.py

├── evidence/
│   ├── confirmed/
│   │   ├── hyp_001.json          ← Now with "action" field
│   │   └── hyp_002.json
│   ├── disproven/
│   └── unclear/

└── pocs/
    ├── shell_injection.sh
    └── path_traversal.zip
```

---

## Example: Shell Injection → Control → Patch

### Step 1: Enumerate Surface (SURFACES.yaml)

```yaml
- id: upload_shell_injection
  entrypoint: "POST /api/upload (multipart filename)"
  sink: "popen(unzip -d /tmp + filename)"
  recommended_control: "C-001"
  default_fix: "replace popen() with safe_exec(argv)"
```

### Step 2: Hypothesize (hyp_001.md with Ralphization)

```markdown
# REACHABILITY
filename from HTTP → unzip.c:92 → popen() → /bin/sh

# SINK
popen() at src/unzip.c:92

# CONTROL
C-001: Shell Execution Wrapper

# PATCH
src/unzip.c:92: Replace popen(cmd_string) with safe_exec(argv)

# TEST
test_shell_injection_blocked(): Fuzz with shell metacharacters
```

### Step 3: Test & Confirm

```bash
zip test.zip file.txt
mv test.zip '`id`.zip'
curl -F 'file=@`id`.zip' http://localhost/api/upload
# Response contains "uid=1000" → CONFIRMED
```

### Step 4: Record Evidence with Action (evidence/confirmed/hyp_001.json)

```json
{
  "hypothesis_id": "hyp_001",
  "status": "confirmed",
  "action": "PATCH",                  ← Required!
  "control_id": "C-001",
  "patch_location": "src/unzip.c:92",
  "test_case": "test_shell_injection_blocked()",
  "code_location": "src/unzip.c:92",
  "description": "Shell injection via filename"
}
```

### Step 5: Create Control Document (controls/C-001_shell_exec_guard.md)

```markdown
# Control: C-001 Shell Execution Wrapper

## Implementation

def safe_exec(argv: List[str]) -> int:
    """Execute command with argv array, never shell string"""
    return subprocess.run(argv, shell=False)

# BEFORE: system("unzip -d /tmp " + filename)
# AFTER:  safe_exec(["unzip", "-d", "/tmp", filename])
```

### Step 6: Create Patch (patches/P-001_safe_exec_wrapper/)

```
patches/P-001_safe_exec_wrapper/
├── implementation.md
├── patch.diff
├── test_regression.py
└── pr_template.md
```

### Step 7: View Control Map Report

```bash
python3 -c "from chiefwiggum import Evaluator; e = Evaluator('.'); print(e.control_map_report())"
```

```
PATCHES READY (1 item) ← Start here
[hyp_001] Shell injection in unzip
  Location: src/unzip.c:92
  Test: test_shell_injection_blocked()
```

**Now you have a PR-ready patch, backed by evidence, structured by controls, ready to deploy.**

---

## Evidence Schema (ChiefWiggum++)

All evidence must include:

```python
@dataclass
class Evidence:
    hypothesis_id: str
    status: EvidenceType          # confirmed, disproven, unclear
    action: ActionType            # REQUIRED: PATCH, CONTROL, INSTRUMENT, BLOCKER

    # If PATCH:
    patch_location: str           # file:line to modify
    test_case: str                # regression test name

    # If CONTROL:
    control_id: str               # C-001 through C-012

    # If INSTRUMENT:
    instrumentation: str          # what data would resolve this?

    # If BLOCKER:
    blocking_reason: str          # why is it safe?
```

**No empty actions.** If you don't know the action, the hypothesis isn't done.

---

## The 12 Controls At a Glance

**Remember these, use these everywhere:**

```
EXECUTION (4):
  C-001: Shell Execution Wrapper (no popen/system/spawn)
  C-002: Argument Allowlist (no shell syntax)
  C-010: Rate Limits + Size Caps
  C-011: Privilege Drop + Sandbox

PARSER (4):
  C-005: YAML Safe Loader Only
  C-006: XXE Disabled
  C-007: Deserialization Allowlist/Ban
  C-009: Template Sandboxing

IO (2):
  C-003: Path Canonicalization + Allowlist
  C-004: Safe Archive Extract (no symlinks, no .., size limits)

AUTHZ (2):
  C-012: Audit Logging on Trust Boundaries
  (C-011 listed above for privilege drop)

NETWORK (1):
  C-008: SSRF Outbound Allowlist + DNS Pinning
```

---

## Integration

### Python API

```python
from chiefwiggum import Evaluator

evaluator = Evaluator("./my_audit")

# Record a PATCH
evaluator.test_hypothesis(
    hypothesis_id="hyp_001",
    confirmed=True,
    code_location="src/unzip.c:92",
    description="Shell injection in unzip",
    action="PATCH",                          # ChiefWiggum++
    control_id="C-001",
    patch_location="src/unzip.c:92",
    test_case="test_shell_injection_blocked()"
)

# Get Ralph-style report
print(evaluator.control_map_report())
```

### CLI

```bash
chiefwiggum init my_audit
chiefwiggum record hyp_001 \
  --confirmed \
  --action PATCH \
  --location "src/unzip.c:92" \
  --control "C-001" \
  --test "test_shell_injection_blocked()"

chiefwiggum control-map     # Ralph-style report
```

---

## Success Metrics

After a week with ChiefWiggum++, you should be able to answer:

**"How much safer is the repo now?"**
→ Read CONTROL_MAP report: 3 patches deployed, 2 controls in progress

**"What's left?"**
→ Read CONTROL_MAP: 4 items "CONTROLS NEEDED", 1 item "INSTRUMENTATION NEEDED"

**"Did we regress?"**
→ Run test suite from CONTROL library: All passing

**"Why is this vulnerability even a threat?"**
→ Read SURFACES.yaml Ralph metadata: entrypoint → sink → control

---

## Status: ChiefWiggum++ Ready

```
✓ ActionType requirement (PATCH | CONTROL | INSTRUMENT | BLOCKER)
✓ 12-control standard library (C-001 through C-012)
✓ Ralph metadata in SURFACES.yaml
✓ Control Map report generation
✓ Evidence schema with required action field
✓ Templates for controls/ and patches/
✓ Ralphization checklist (15 min per hypothesis)
✓ Python API + CLI
```

**D'oh!** — Now you've got a patch pipeline that converges.

