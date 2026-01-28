"""
Multi-stage attack chain detectors for ChiefWiggum Loop

Detects complex vulnerability chains that single-function pattern matching misses.
Framework for detecting sophisticated multi-stage attacks.
"""

from pathlib import Path
from typing import List, Dict, Optional, Tuple
import re


class AttackChainDetector:
    """Detect multi-stage vulnerability chains"""

    def __init__(self, codebase_path: Path):
        self.codebase = Path(codebase_path)
        self.findings = []


    def detect_protocol_injection_in_broker_config(self) -> List[Dict]:
        """
        Detect URI protocol injection in broker configuration loading

        Looks for code that:
        1. Accepts user-controlled URI parameters (like brokerConfig)
        2. Doesn't validate protocol scheme (should only allow file://)
        3. Loads configuration from the parameter without restriction
        """
        findings = []

        # Find files that handle broker configuration loading
        broker_files = list(self.codebase.rglob("*Broker*.java"))

        for broker_file in broker_files:
            try:
                content = broker_file.read_text()
            except:
                continue

            # Look for configuration URI loading patterns
            config_patterns = [
                (r"(?:config|uri|URL|url).*?(?:query|parameter|param)", "Configuration parameter"),
                (r"(?:brokerConfig|brokerURI|configUrl)", "Broker config reference"),
                (r"(?:createBroker|loadConfig|parseUri)", "Config loading function"),
            ]

            for pattern, desc in config_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    # Check if protocol is validated
                    if "http" in content.lower() and not any(
                        validation in content for validation in ["allowlist", "whitelist", "startsWith", "file://"]
                    ):
                        # Check if it's actually loading remote resources
                        if any(load in content for load in ["URL", "openConnection", "openStream", "new URL"]):
                            finding = {
                                "id": "hyp_broker_config_protocol_injection",
                                "title": f"Protocol Injection in Broker Configuration via {desc}",
                                "severity": "HIGH",
                                "file": str(broker_file),
                                "description": f"Configuration loading accepts {desc} without protocol validation",
                                "risk": "HTTP/HTTPS protocol allows SSRF and remote code loading",
                                "action": "PATCH"
                            }
                            findings.append(finding)
                            break

        return findings

    def _extract_code_snippet(self, content: str, marker: str, lines: int = 5) -> str:
        """Extract code snippet around a marker"""
        lines_list = content.split("\n")
        snippet_lines = []

        for i, line in enumerate(lines_list):
            if marker in line:
                # Get context lines
                start = max(0, i - 2)
                end = min(len(lines_list), i + lines)
                snippet_lines = lines_list[start:end]
                break

        return "\n".join(snippet_lines[:10])  # Return up to 10 lines

    def detect_all(self) -> List[Dict]:
        """Run all attack chain detectors"""
        all_findings = []

        # Run protocol injection detector only
        all_findings.extend(self.detect_protocol_injection_in_broker_config())

        # Deduplicate by ID
        seen_ids = set()
        unique_findings = []
        for finding in all_findings:
            if finding["id"] not in seen_ids:
                unique_findings.append(finding)
                seen_ids.add(finding["id"])

        return unique_findings


def detect_attack_chains(codebase_path: Path) -> List[Dict]:
    """
    Public interface for attack chain detection

    Args:
        codebase_path: Path to the codebase to analyze

    Returns:
        List of detected attack chain vulnerabilities
    """
    detector = AttackChainDetector(codebase_path)
    return detector.detect_all()
