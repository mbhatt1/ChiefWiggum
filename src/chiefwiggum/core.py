"""
Core ChiefWiggum Loop implementation - Evaluator, Evidence Ledger, Surface Enumeration

ChiefWiggum++ edition: Every hypothesis closes with an actionable output.
"""

import json
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict
from enum import Enum


class EvidenceType(Enum):
    """Classification of evidence outcomes"""
    CONFIRMED = "confirmed"
    DISPROVEN = "disproven"
    UNCLEAR = "unclear"


class ActionType(Enum):
    """What action closes this hypothesis"""
    PATCH = "PATCH"          # Confirmed, has patch
    CONTROL = "CONTROL"      # Confirmed, needs control (hardening suggestion)
    INSTRUMENT = "INSTRUMENT"  # Unclear, needs instrumentation to resolve
    BLOCKER = "BLOCKER"      # Disproven, but records why


@dataclass
class Evidence:
    """Single piece of evidence about a vulnerability hypothesis

    ChiefWiggum++ requirement: Every evidence entry must have an action.
    No hypothesis ends as just "notes".
    """
    hypothesis_id: str
    code_location: str
    status: EvidenceType
    description: str
    test_date: str
    details: Dict

    # ChiefWiggum++ fields - REQUIRED
    action: ActionType = ActionType.PATCH  # REQUIRED: What do we do about this?
    control_id: Optional[str] = None       # If CONTROL, which control (C-001, etc)?
    patch_location: Optional[str] = None   # If PATCH, file/function to modify
    test_case: Optional[str] = None        # If PATCH, regression test requirement
    blocking_reason: Optional[str] = None  # If DISPROVEN, why is it safe?
    instrumentation: Optional[str] = None  # If UNCLEAR, what data would resolve it?

    def validate(self):
        """Ensure evidence has complete action"""
        if not self.action:
            raise ValueError(f"Evidence {self.hypothesis_id} has no action. "
                           "Must be PATCH, CONTROL, INSTRUMENT, or BLOCKER")

        if self.action == ActionType.CONTROL and not self.control_id:
            raise ValueError(f"{self.hypothesis_id}: CONTROL action requires control_id")

        if self.action == ActionType.PATCH and not self.patch_location:
            raise ValueError(f"{self.hypothesis_id}: PATCH action requires patch_location")

        if self.action == ActionType.INSTRUMENT and not self.instrumentation:
            raise ValueError(f"{self.hypothesis_id}: INSTRUMENT action requires instrumentation")


@dataclass
class Hypothesis:
    """A testable claim about a vulnerability"""
    id: str
    claim: str
    path: str
    proof_required: str
    surface_id: str
    status: str  # pending, testing, confirmed, disproven


class EvidenceLedger:
    """
    Persistent memory of tested hypotheses.

    This is the secret sauce - prevents re-testing.
    """

    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        self.evidence_dir = self.project_root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        for subdir in ["confirmed", "disproven", "unclear"]:
            (self.evidence_dir / subdir).mkdir(exist_ok=True)

        self.ledger: List[Evidence] = []
        self._load_ledger()

    def _load_ledger(self):
        """Load existing evidence from disk"""
        for evidence_type in EvidenceType:
            evidence_path = self.evidence_dir / evidence_type.value
            if not evidence_path.exists():
                continue

            for file in evidence_path.glob("*.json"):
                with open(file) as f:
                    data = json.load(f)
                    # Convert back to Evidence object
                    evidence = Evidence(
                        hypothesis_id=data["hypothesis_id"],
                        code_location=data["code_location"],
                        status=EvidenceType(data["status"]),
                        description=data["description"],
                        test_date=data["test_date"],
                        details=data.get("details", {})
                    )
                    self.ledger.append(evidence)

    def add_evidence(self, hypothesis_id: str, evidence_type: EvidenceType,
                     code_location: str, description: str, details: Dict = None,
                     action: ActionType = ActionType.PATCH,
                     control_id: Optional[str] = None,
                     patch_location: Optional[str] = None,
                     test_case: Optional[str] = None,
                     blocking_reason: Optional[str] = None,
                     instrumentation: Optional[str] = None):
        """Record a test result with actionable output (ChiefWiggum++)

        REQUIRED: Must specify action (PATCH, CONTROL, INSTRUMENT, BLOCKER)
        """
        evidence = Evidence(
            hypothesis_id=hypothesis_id,
            code_location=code_location,
            status=evidence_type,
            description=description,
            test_date=datetime.now().isoformat(),
            details=details or {},
            action=action,
            control_id=control_id,
            patch_location=patch_location,
            test_case=test_case,
            blocking_reason=blocking_reason,
            instrumentation=instrumentation,
        )

        # Validate before persisting
        evidence.validate()

        self.ledger.append(evidence)

        # Persist to disk
        file_path = (self.evidence_dir / evidence_type.value /
                     f"{hypothesis_id}.json")
        with open(file_path, "w") as f:
            json.dump(asdict(evidence), f, indent=2, default=str)

    def has_been_tested(self, hypothesis_id: str) -> bool:
        """Check if hypothesis was already tested"""
        return any(e.hypothesis_id == hypothesis_id for e in self.ledger)

    def was_confirmed(self, hypothesis_id: str) -> bool:
        """Check if hypothesis was confirmed"""
        return any(
            e.hypothesis_id == hypothesis_id and
            e.status == EvidenceType.CONFIRMED
            for e in self.ledger
        )

    def was_disproven(self, hypothesis_id: str) -> bool:
        """Check if hypothesis was disproven"""
        return any(
            e.hypothesis_id == hypothesis_id and
            e.status == EvidenceType.DISPROVEN
            for e in self.ledger
        )

    def get_evidence(self, hypothesis_id: str) -> Optional[Evidence]:
        """Get evidence for a specific hypothesis"""
        for e in self.ledger:
            if e.hypothesis_id == hypothesis_id:
                return e
        return None

    def list_confirmed(self) -> List[Evidence]:
        """Get all confirmed vulnerabilities"""
        return [e for e in self.ledger if e.status == EvidenceType.CONFIRMED]

    def list_disproven(self) -> List[Evidence]:
        """Get all disproven hypotheses"""
        return [e for e in self.ledger if e.status == EvidenceType.DISPROVEN]

    def list_unclear(self) -> List[Evidence]:
        """Get all unclear results"""
        return [e for e in self.ledger if e.status == EvidenceType.UNCLEAR]

    def summary(self) -> Dict:
        """Get summary statistics"""
        return {
            "total_tested": len(self.ledger),
            "confirmed": len(self.list_confirmed()),
            "disproven": len(self.list_disproven()),
            "unclear": len(self.list_unclear()),
        }


class SurfaceEnumerator:
    """
    Enumerate reachable attack surfaces.

    Identifies entry points and data flows to dangerous sinks.
    """

    def __init__(self, source_root: Path):
        self.source_root = Path(source_root)
        self.surfaces: List[Dict] = []

    def find_dangerous_functions(self) -> List[str]:
        """List of functions to watch for (sinks)"""
        return [
            "popen", "system", "execve", "exec",
            "eval", "exec", "compile",
            "malloc", "calloc", "realloc",
            "strcpy", "strcat", "sprintf",
            "memcpy", "memmove",
        ]

    def enumerate(self) -> List[Dict]:
        """Enumerate surfaces (basic implementation)"""
        # In real implementation, would parse source code
        # For now, return empty - users fill this manually
        return self.surfaces


class Evaluator:
    """
    Main testing harness for vulnerability analysis.

    Orchestrates the ChiefWiggum loop:
    1. Define target
    2. Enumerate surfaces
    3. Form hypotheses
    4. Test
    5. Record evidence
    """

    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        self.ledger = EvidenceLedger(self.project_root)
        self.enumerator = SurfaceEnumerator(self.project_root)
        self.hypotheses: List[Hypothesis] = []
        self.confirmed_count = 0
        self.disproven_count = 0

    def test_hypothesis(self, hypothesis_id: str, confirmed: bool,
                        code_location: str, description: str,
                        details: Dict = None) -> bool:
        """
        Test a hypothesis and record result.

        Args:
            hypothesis_id: Unique ID for this hypothesis
            confirmed: True if vulnerability exists
            code_location: File:line of vulnerable code
            description: What we learned
            details: Additional metadata

        Returns:
            True if test succeeded, False if skipped (already tested)
        """
        # Check if already tested
        if self.ledger.has_been_tested(hypothesis_id):
            print(f"⚠️  Already tested: {hypothesis_id}")
            return False

        # Record result
        if confirmed:
            evidence_type = EvidenceType.CONFIRMED
            self.confirmed_count += 1
        else:
            evidence_type = EvidenceType.DISPROVEN
            self.disproven_count += 1

        self.ledger.add_evidence(
            hypothesis_id=hypothesis_id,
            evidence_type=evidence_type,
            code_location=code_location,
            description=description,
            details=details
        )

        return True

    def skip_hypothesis(self, hypothesis_id: str) -> bool:
        """Check if hypothesis should be skipped (already tested)"""
        return self.ledger.has_been_tested(hypothesis_id)

    def get_summary(self) -> Dict:
        """Get testing summary"""
        summary = self.ledger.summary()
        summary.update({
            "tested_in_session": self.confirmed_count + self.disproven_count,
            "confirmed_in_session": self.confirmed_count,
            "disproven_in_session": self.disproven_count,
        })
        return summary

    def report(self) -> str:
        """Generate evaluation report"""
        summary = self.get_summary()

        report = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                    CHIEFWIGGUM LOOP EVALUATION REPORT                      ║
╚════════════════════════════════════════════════════════════════════════════╝

Confirmed:      {summary['confirmed']}/10 ✓
Disproven:      {summary['disproven']}/10 ✗
Unclear:        {summary['unclear']}/10 ?
Total Tested:   {summary['total_tested']}/10

Session Progress:
  • Confirmed: {summary['confirmed_in_session']}
  • Disproven: {summary['disproven_in_session']}

Evidence Ledger Prevents Re-testing: YES ✓

D'oh! — ChiefWiggum Loop
        """
        return report

    def control_map_report(self) -> str:
        """Generate Ralph-style Control Map report

        Groups evidence by control category and action type.
        This is what makes ChiefWiggum++ effective like Ralph.
        """
        from .control import ControlCategory, STANDARD_CONTROLS

        report = """
╔════════════════════════════════════════════════════════════════════════════╗
║                     CHIEFWIGGUM++ CONTROL MAP REPORT                       ║
║                   (Ralph-effective hardening backlog)                      ║
╚════════════════════════════════════════════════════════════════════════════╝

Generated: {date}

This report groups all findings by control category and action type.
Use this to prioritize hardening work and track progress.

""".format(date=datetime.now().isoformat())

        # Group evidence by action type
        patches = [e for e in self.ledger.ledger if e.action == ActionType.PATCH]
        controls = [e for e in self.ledger.ledger if e.action == ActionType.CONTROL]
        instrumentation = [e for e in self.ledger.ledger if e.action == ActionType.INSTRUMENT]
        blockers = [e for e in self.ledger.ledger if e.action == ActionType.BLOCKER]

        # Patches (highest priority)
        report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATCHES READY ({len(patches)} items) ← Start here for quick wins
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        for evidence in patches:
            report += f"""
  [{evidence.hypothesis_id}] {evidence.description}
    Location: {evidence.patch_location}
    Test: {evidence.test_case}
    Status: ✓ CONFIRMED
"""

        # Controls (group by category)
        report += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTROLS NEEDED ({len(controls)} items) ← Deploy these hardening controls
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        for evidence in controls:
            control = STANDARD_CONTROLS.get(evidence.control_id, None)
            control_name = control.name if control else evidence.control_id
            report += f"""
  [{evidence.hypothesis_id}] {evidence.description}
    Control: {evidence.control_id} ({control_name})
    Status: ✓ CONFIRMED, needs {evidence.control_id}
"""

        # Instrumentation (unresolved, needs data)
        report += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INSTRUMENTATION NEEDED ({len(instrumentation)} items) ← Add tracing/logging to resolve
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        for evidence in instrumentation:
            report += f"""
  [{evidence.hypothesis_id}] {evidence.description}
    Missing: {evidence.instrumentation}
    Status: ? UNCLEAR until above data available
"""

        # Blockers (disproven, reasons documented)
        report += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BLOCKERS / SAFE SURFACES ({len(blockers)} items) ← These don't need fixes (yet)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        for evidence in blockers:
            report += f"""
  [{evidence.hypothesis_id}] {evidence.description}
    Reason: {evidence.blocking_reason}
    Status: ✗ DISPROVEN
"""

        # Control Library Summary
        report += """

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTROL LIBRARY REFERENCE (12 Standard Controls)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTION CONTROLS:
  C-001: Shell Execution Wrapper (no raw system/popen/spawn)
  C-002: Argument Allowlist + No Shell Parsing
  C-010: Rate Limits + Payload Size Caps

PARSER CONTROLS:
  C-005: YAML Safe Loader Only
  C-006: XML External Entities (XXE) Disabled
  C-007: Deserialization Allowlist/Ban
  C-009: Template Rendering Sandboxing

IO CONTROLS:
  C-003: Path Canonicalization + Allowlist
  C-004: Zip/Tar Safe Extract (no symlinks, no .., size limits)

AUTHZ CONTROLS:
  C-011: Privilege Drop + Sandbox Around Risky Ops
  C-012: Audit Logging on Trust Boundaries

NETWORK CONTROLS:
  C-008: SSRF Outbound Allowlist + DNS Pinning


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Ready to patch:        {patches} items
Ready for control:     {controls} items
Needs instrumentation: {instrumentation} items
Documented as safe:    {blockers} items

Next step: Implement patches and controls in order above.
Every hypothesis closes with an action (PATCH | CONTROL | INSTRUMENT | BLOCKER).

D'oh! — ChiefWiggum++
""".format(patches=len(patches), controls=len(controls),
           instrumentation=len(instrumentation), blockers=len(blockers))

        return report
