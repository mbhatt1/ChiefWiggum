"""
Core ChiefWiggum Loop implementation - Evaluator, Evidence Ledger, Surface Enumeration
ChiefWiggum++ edition: Every hypothesis closes with an actionable output.

ENHANCED: Now includes semantic analysis alongside pattern matching.
"""

import json
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
from enum import Enum
import sys
import os

# Add semantic analyzer if available
try:
    # Try to import from benchmark location first
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "benchmark"))
    from chiefwiggum.semantic import SemanticAnalyzer
    SEMANTIC_AVAILABLE = True
except ImportError:
    SEMANTIC_AVAILABLE = False
    SemanticAnalyzer = None

# Add OpenAI LLM support if available
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    openai = None


class EvidenceType(Enum):
    """Classification of evidence outcomes"""
    CONFIRMED = "confirmed"
    DISPROVEN = "disproven"
    UNCLEAR = "unclear"


class ActionType(Enum):
    """What action closes this hypothesis"""
    PATCH = "PATCH"
    CONTROL = "CONTROL"
    INSTRUMENT = "INSTRUMENT"
    BLOCKER = "BLOCKER"


@dataclass
class Evidence:
    """Single piece of evidence about a vulnerability hypothesis

    ChiefWiggum++ requirement: Every evidence entry must have an action.
    No hypothesis ends as just "notes".
    """
    hypothesis_id: str
    code_location: str
    status: str  # Will be EvidenceType value
    description: str
    test_date: str
    details: Dict

    # ChiefWiggum++ fields - REQUIRED
    action: str = "PATCH"
    control_id: Optional[str] = None
    patch_location: Optional[str] = None
    test_case: Optional[str] = None
    blocking_reason: Optional[str] = None
    instrumentation: Optional[str] = None

    def validate(self):
        """Ensure evidence has complete action"""
        if not self.action:
            raise ValueError(f"Evidence {self.hypothesis_id} has no action. "
                           "Must be PATCH, CONTROL, INSTRUMENT, or BLOCKER")

        if self.action == "CONTROL" and not self.control_id:
            raise ValueError(f"{self.hypothesis_id}: CONTROL action requires control_id")

        if self.action == "PATCH" and not self.patch_location:
            raise ValueError(f"{self.hypothesis_id}: PATCH action requires patch_location")

        if self.action == "INSTRUMENT" and not self.instrumentation:
            raise ValueError(f"{self.hypothesis_id}: INSTRUMENT action requires instrumentation")


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
        for evidence_type in ["confirmed", "disproven", "unclear"]:
            type_dir = self.evidence_dir / evidence_type
            if type_dir.exists():
                for json_file in type_dir.glob("*.json"):
                    try:
                        with open(json_file) as f:
                            data = json.load(f)
                            evidence = Evidence(**data)
                            self.ledger.append(evidence)
                    except Exception as e:
                        print(f"Warning: Failed to load {json_file}: {e}")

    def add_evidence(self, hypothesis_id: str, evidence_type: str, code_location: str,
                    description: str, action: str = "PATCH", control_id: str = None,
                    patch_location: str = None, test_case: str = None,
                    blocking_reason: str = None, instrumentation: str = None):
        """Record a piece of evidence"""
        evidence = Evidence(
            hypothesis_id=hypothesis_id,
            code_location=code_location,
            status=evidence_type,
            description=description,
            test_date=datetime.now().isoformat(),
            details={},
            action=action,
            control_id=control_id,
            patch_location=patch_location,
            test_case=test_case,
            blocking_reason=blocking_reason,
            instrumentation=instrumentation,
        )

        evidence.validate()
        self.ledger.append(evidence)
        self._save_evidence(evidence)

    def _save_evidence(self, evidence: Evidence):
        """Save evidence to disk"""
        type_dir = self.evidence_dir / evidence.status
        type_dir.mkdir(exist_ok=True)

        file_path = type_dir / f"{evidence.hypothesis_id}.json"
        with open(file_path, "w") as f:
            json.dump(asdict(evidence), f, indent=2)

    def list_confirmed(self) -> List[Evidence]:
        """Get all confirmed vulnerabilities"""
        return [e for e in self.ledger if e.status == "confirmed"]

    def list_disproven(self) -> List[Evidence]:
        """Get all disproven hypotheses"""
        return [e for e in self.ledger if e.status == "disproven"]

    def list_unclear(self) -> List[Evidence]:
        """Get all unclear cases"""
        return [e for e in self.ledger if e.status == "unclear"]


class Evaluator:
    """
    Main evaluation engine for ChiefWiggum Loop.
    Coordinates hypothesis testing and evidence collection.

    ENHANCED: Now combines pattern matching + semantic analysis for better detection.
    """

    def __init__(self, project_root: Path, model: str = None, base_url: str = None):
        self.project_root = Path(project_root)
        self.ledger = EvidenceLedger(self.project_root)

        # Initialize semantic analyzer if available
        self.semantic_analyzer = None
        if SEMANTIC_AVAILABLE:
            try:
                self.semantic_analyzer = SemanticAnalyzer()
            except Exception as e:
                print(f"Warning: Semantic analyzer not available: {e}")

        # Initialize OpenAI LLM if available
        # Support custom base_url for local LLMs (e.g., Ollama)
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o")
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL")

        self.openai_client = None
        api_key = os.getenv("OPENAI_API_KEY")

        # For local LLMs with custom base_url, use dummy key if not set
        if self.base_url and not api_key:
            api_key = "ollama"

        self.use_llm = (api_key is not None or self.base_url is not None) and OPENAI_AVAILABLE
        if self.use_llm:
            try:
                if self.base_url:
                    self.openai_client = openai.OpenAI(api_key=api_key, base_url=self.base_url)
                else:
                    self.openai_client = openai.OpenAI(api_key=api_key)
            except Exception as e:
                print(f"Warning: OpenAI LLM not available: {e}")
                self.use_llm = False

    def analyze(self, code: str, filepath: str = None) -> Dict:
        """
        Comprehensive analysis combining pattern + semantic methods.
        If OpenAI API is available, uses LLM-based analysis for higher accuracy.

        Args:
            code: Source code to analyze
            filepath: Path to source file (for context)

        Returns:
            Dictionary with detection results from both methods
        """
        results = {
            "pattern": [],
            "semantic": [],
            "llm": [],
            "combined": [],
            "sources": {}
        }

        # Step 1: Pattern-based detection (if implemented)
        # This would be filled in by subclasses or pattern detectors

        # Step 2: Semantic analysis (if available)
        if self.semantic_analyzer:
            try:
                semantic_results = self.semantic_analyzer.analyze(code, filepath or "unknown")
                results["semantic"] = semantic_results
            except Exception as e:
                print(f"Semantic analysis error: {e}")
                results["semantic"] = []

        # Step 3: LLM-based analysis (if OpenAI available) - for maximum accuracy
        if self.use_llm and self.openai_client:
            try:
                llm_results = self._analyze_with_llm(code, filepath or "unknown")
                results["llm"] = llm_results
            except Exception as e:
                print(f"LLM analysis error: {e}")
                results["llm"] = []

        # Step 4: Merge results (prioritize LLM > semantic > pattern)
        results["combined"] = self._merge_results(results["pattern"], results["semantic"], results["llm"])

        return results

    def _analyze_with_llm(self, code: str, filepath: str) -> List[Dict]:
        """
        Analyze code using LLM for maximum accuracy vulnerability detection.

        Args:
            code: Source code to analyze
            filepath: Path for context

        Returns:
            List of detected vulnerabilities with detailed analysis
        """
        try:
            prompt = f"""You are a security researcher analyzing code for vulnerabilities.

FILE: {filepath}

CODE:
```
{code[:5000]}
```

Find ALL vulnerabilities. For each vulnerability, provide:
1. Type (e.g., RCE, XXE, SQL Injection, Deserialization, etc.)
2. Severity (CRITICAL, HIGH, MEDIUM, LOW)
3. Confidence level: HIGH (definite vulnerability), MEDIUM (likely vulnerability), LOW (possible issue)
4. CWE number
5. Location (line/function)
6. Description of the issue
7. Impact
8. How to fix it

Format as JSON array. Example:
[
  {{
    "type": "Deserialization RCE",
    "severity": "CRITICAL",
    "confidence": "HIGH",
    "cwe": "CWE-502",
    "location": "line 45, method createThrowable()",
    "description": "ObjectInputStream.readObject() called without validation",
    "impact": "Remote code execution via gadget chain",
    "fix": "Add class allowlist before deserialization"
  }}
]

Return ONLY valid JSON array, no other text.
"""

            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security researcher analyzing code for vulnerabilities. Always respond with valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=1000
            )

            response_text = response.choices[0].message.content

            # Extract JSON array from response
            import re
            json_match = re.search(r'\[[\s\S]*\]', response_text)
            if json_match:
                vulnerabilities = json.loads(json_match.group())
                return vulnerabilities if isinstance(vulnerabilities, list) else []
            return []

        except Exception as e:
            print(f"LLM analysis exception: {e}")
            return []

    def _merge_results(self, pattern_results: List[Dict], semantic_results: List[Dict], llm_results: List[Dict] = None) -> List[Dict]:
        """
        Merge pattern + semantic + LLM results, deduplicate, and boost confidence.
        LLM results have highest priority (best accuracy), then semantic, then pattern.

        Args:
            pattern_results: Results from pattern matching
            semantic_results: Results from semantic analysis
            llm_results: Results from LLM analysis (highest priority)

        Returns:
            Merged and deduplicated vulnerability list
        """
        if llm_results is None:
            llm_results = []

        merged = {}

        # Step 1: Add LLM results first (highest priority for accuracy)
        for l in llm_results:
            key = (l.get('type', 'unknown'), l.get('location', 'unknown'))
            merged[key] = {
                **l,
                'sources': ['llm'],
                'confidence_score': 95 if l.get('confidence', '').upper() == 'HIGH' else (70 if l.get('confidence', '').upper() == 'MEDIUM' else 50)
            }

        # Step 2: Add pattern results
        for p in pattern_results:
            key = (p.get('type', 'unknown'), p.get('location', 'unknown'))
            if key not in merged:
                merged[key] = {
                    **p,
                    'sources': ['pattern'],
                    'confidence_score': p.get('confidence_score', 60)
                }
            else:
                # Already found by LLM, just add source
                merged[key]['sources'].insert(0, 'pattern')

        # Step 3: Add/merge semantic results
        for s in semantic_results:
            key = (s.get('type', 'unknown'), s.get('location', 'unknown'))
            if key in merged:
                # Already found by LLM or pattern - boost confidence
                merged[key]['sources'].append('semantic')
                merged[key]['confidence_score'] = min(100, merged[key].get('confidence_score', 60) + 15)
            else:
                # Only semantic found it
                merged[key] = {
                    **s,
                    'sources': ['semantic'],
                    'confidence_score': s.get('confidence_score', 70)
                }

        return list(merged.values())

    def get_summary(self) -> Dict:
        """Get summary of test results"""
        return {
            "confirmed": len(self.ledger.list_confirmed()),
            "disproven": len(self.ledger.list_disproven()),
            "unclear": len(self.ledger.list_unclear()),
            "total": len(self.ledger.ledger),
        }

    def control_map_report(self) -> str:
        """Generate a control mapping report"""
        output = []
        output.append("\n" + "=" * 80)
        output.append("ChiefWiggum Control Map Report")
        output.append("=" * 80 + "\n")

        # Get all confirmed vulnerabilities
        confirmed = self.ledger.list_confirmed()
        if confirmed:
            output.append("CONFIRMED VULNERABILITIES (Require Action)\n")
            output.append("-" * 80)

            # Group by control
            by_control = {}
            by_action = {"PATCH": [], "CONTROL": [], "INSTRUMENT": []}

            for evidence in confirmed:
                if evidence.action in by_action:
                    by_action[evidence.action].append(evidence)

                if evidence.control_id:
                    if evidence.control_id not in by_control:
                        by_control[evidence.control_id] = []
                    by_control[evidence.control_id].append(evidence)

            # Report by action type
            if by_action["PATCH"]:
                output.append(f"\nPATCHES REQUIRED ({len(by_action['PATCH'])})")
                output.append("-" * 40)
                for e in by_action["PATCH"]:
                    output.append(f"  {e.hypothesis_id}")
                    output.append(f"    Location: {e.patch_location}")
                    output.append(f"    Test: {e.test_case or 'Not specified'}")
                    output.append("")

            if by_action["CONTROL"]:
                output.append(f"\nCONTROLS NEEDED ({len(by_action['CONTROL'])})")
                output.append("-" * 40)
                for e in by_action["CONTROL"]:
                    output.append(f"  {e.hypothesis_id}")
                    output.append(f"    Control: {e.control_id}")
                    output.append(f"    Description: {e.description}")
                    output.append("")

            if by_action["INSTRUMENT"]:
                output.append(f"\nINSTRUMENTATION NEEDED ({len(by_action['INSTRUMENT'])})")
                output.append("-" * 40)
                for e in by_action["INSTRUMENT"]:
                    output.append(f"  {e.hypothesis_id}")
                    output.append(f"    Data needed: {e.instrumentation}")
                    output.append("")

        # Summary
        summary = self.get_summary()
        output.append("\n" + "=" * 80)
        output.append("Summary")
        output.append("=" * 80)
        output.append(f"Confirmed:  {summary['confirmed']}")
        output.append(f"Disproven:  {summary['disproven']}")
        output.append(f"Unclear:    {summary['unclear']}")
        output.append("=" * 80 + "\n")

        return "\n".join(output)
