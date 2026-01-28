# ChiefWiggum Skill Guide

## Overview

ChiefWiggum is a vulnerability testing methodology that enforces **every hypothesis closes with an actionable output**—no vague notes.

The skill provides a structured loop:
1. **Define** target and threat model
2. **Enumerate** attack surfaces
3. **Form** testable hypotheses using the Ralphization Checklist
4. **Test** each hypothesis against code
5. **Record** evidence (confirmed/disproven/unclear)
6. **Report** on hardening backlog prioritized by action type

## Commands

### `chiefwiggum init --target-url <url>`

Initialize a new vulnerability analysis project in the current directory.

**Example:**
```bash
/chiefwiggum init --target-url https://github.com/apache/activemq
```

**What it creates:**
- `chiefwiggum.json` - Project metadata
- `ground_truth/TARGET.md` - Threat model and success criteria
- `surfaces/SURFACES.yaml` - Attack surface enumeration
- `hypotheses/template.md` - Template for forming hypotheses
- `controls/`, `patches/`, `examples/` - Output directories
- `evidence/` - Persistent ledger of test results

### `chiefwiggum analyze --surface <file> --hypothesis <file>`

Test a hypothesis against enumerated attack surfaces.

### `chiefwiggum ledger list`

View all tested hypotheses organized by status.

### `chiefwiggum report generate`

Generate a prioritized hardening backlog with patches, controls, and instrumentation needs.

## The Ralphization Checklist

Every hypothesis must fill out 5 required fields:

1. **REACHABILITY:** Exact entry point → dangerous sink
2. **SINK:** What function/API is dangerous?
3. **CONTROL:** Which C-001 to C-012 blocks this?
4. **PATCH:** File/function to change
5. **TEST:** Regression test to prevent regression

## The 12 Standard Controls

- **C-001:** Shell Execution Wrapper
- **C-002:** Argument Allowlist + No Shell Parsing
- **C-003:** Path Canonicalization + Allowlist
- **C-004:** Zip/Tar Safe Extract
- **C-005:** YAML Safe Loader Only
- **C-006:** XXE Disabled
- **C-007:** Deserialization Allowlist/Ban
- **C-008:** SSRF Outbound Allowlist + DNS Pinning
- **C-009:** Template Rendering Sandboxing
- **C-010:** Rate Limits + Payload Size Caps
- **C-011:** Privilege Drop + Sandbox Around Risky Ops
- **C-012:** Audit Logging on Trust Boundaries

## Project Structure

```
.
├── chiefwiggum.json              # Project metadata
├── ground_truth/TARGET.md        # Threat model
├── surfaces/SURFACES.yaml        # Attack surface enumeration
├── hypotheses/                   # Your hypotheses
├── controls/                     # Control implementations
├── patches/                      # Patch examples
├── examples/                     # Reference implementations
└── evidence/                     # Persistent ledger (auto-maintained)
    ├── confirmed/
    ├── disproven/
    └── unclear/
```

## Key Design Principles

1. **Every hypothesis closes with an action** - No vague notes, only PATCH/CONTROL/INSTRUMENT/BLOCKER
2. **Evidence is persistent** - Prevents re-testing
3. **Reachability matters** - Not every vulnerable code is exploitable
4. **Controls are standard** - Use 12 controls consistently
5. **Patches require tests** - Every patch gets a regression test
