"""
Parallel hypothesis validation using Claude LLM
Validates multiple hypotheses concurrently
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple
from .claude_judge import ClaudeJudge


class ParallelValidator:
    """Validates hypotheses in parallel using Claude"""

    def __init__(self, java_files_content: Dict[str, str]):
        self.java_files_content = java_files_content
        self.judge = ClaudeJudge(max_workers=5)

    def extract_code_context(self, evidence_list: List[str]) -> str:
        """Extract code context for evidence files"""
        code_context = ""
        for file_evidence in evidence_list[:2]:
            filename = file_evidence.split(":")[0]
            for full_path, content in self.java_files_content.items():
                if filename in full_path:
                    pattern_text = file_evidence.split(":")[1] if ":" in file_evidence else ""
                    if pattern_text in content:
                        idx = content.find(pattern_text)
                        start = max(0, idx - 500)
                        end = min(len(content), idx + 500)
                        code_context += f"// From {filename}\n{content[start:end]}\n\n"
                    break
        return code_context

    def prepare_batch(
        self,
        hypothesis_files: List[Path],
        code_findings: Dict[str, List[str]]
    ) -> Tuple[List[Dict], Dict[str, str]]:
        """
        Prepare batch of findings for parallel LLM analysis

        Returns:
            (findings_list, code_snippets_dict)
        """
        findings_list = []
        code_snippets = {}

        for hyp_file in hypothesis_files:
            hyp_id = hyp_file.stem
            hyp_content = hyp_file.read_text()

            # Extract sink and control
            sink_match = re.search(r'- Sink:\s*`?([^`\n]+)`?', hyp_content)
            control_match = re.search(r'- Control:\s*\*\*(C-\d+)', hyp_content)
            sink = sink_match.group(1).lower() if sink_match else ""
            control = control_match.group(1) if control_match else "UNKNOWN"

            # Check if any dangerous pattern matches
            evidence_list = []
            for pattern_name, files_found in code_findings.items():
                if files_found and pattern_name.lower() in sink:
                    for filename in files_found[:2]:
                        evidence_list.append(f"{filename}:{pattern_name}")

            # If pattern found, prepare for LLM analysis
            if evidence_list:
                code_context = self.extract_code_context(evidence_list)
                if code_context:
                    finding = {
                        "id": hyp_id,
                        "type": hyp_id,
                        "severity": "UNKNOWN",
                        "location": "; ".join(evidence_list[:2]),
                        "description": f"Dangerous pattern: {evidence_list[0]}",
                        "impact": "Potential security vulnerability"
                    }
                    findings_list.append(finding)
                    code_snippets[hyp_id] = code_context

        return findings_list, code_snippets

    def validate_batch_parallel(
        self,
        findings_list: List[Dict],
        code_snippets: Dict[str, str],
        progress_callback=None
    ) -> Dict[str, Dict]:
        """
        Validate findings in parallel using Claude

        Args:
            findings_list: List of findings to validate
            code_snippets: Dict of {finding_id: code}
            progress_callback: Optional callback for progress

        Returns:
            Dict of {finding_id: judgment}
        """
        if not findings_list:
            return {}

        # Use parallel batch processing
        judgments = self.judge.judge_batch_parallel(
            code_snippets,
            findings_list,
            callback=progress_callback
        )

        return judgments
