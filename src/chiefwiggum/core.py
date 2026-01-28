"""
Core ChiefWiggum Loop implementation - Evaluator, Evidence Ledger, Surface Enumeration
"""

import json
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
from enum import Enum


class EvidenceType(Enum):
    """Classification of evidence outcomes"""
    CONFIRMED = "confirmed"
    DISPROVEN = "disproven"
    UNCLEAR = "unclear"


@dataclass
class Evidence:
    """Single piece of evidence about a vulnerability hypothesis"""
    hypothesis_id: str
    code_location: str
    status: EvidenceType
    description: str
    test_date: str
    details: Dict


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
                     code_location: str, description: str, details: Dict = None):
        """Record a test result"""
        evidence = Evidence(
            hypothesis_id=hypothesis_id,
            code_location=code_location,
            status=evidence_type,
            description=description,
            test_date=datetime.now().isoformat(),
            details=details or {}
        )
        self.ledger.append(evidence)

        # Persist to disk
        file_path = (self.evidence_dir / evidence_type.value /
                     f"{hypothesis_id}.json")
        with open(file_path, "w") as f:
            json.dump(asdict(evidence), f, indent=2)

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
