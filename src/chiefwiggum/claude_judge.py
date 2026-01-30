"""
Claude-based LLM Judge for vulnerability analysis
Uses Claude API instead of OpenAI
Supports async/parallel analysis for performance
"""

import os
import json
from typing import Dict, Optional, List
import anthropic
import asyncio
import concurrent.futures


class ClaudeJudge:
    """Uses Claude to judge vulnerability findings with async support"""

    def __init__(self, model: str = "claude-opus-4-5-20251101", max_workers: int = 5):
        self.model = model
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.max_workers = max_workers
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

    def judge_finding(
        self,
        code: str,
        finding: Dict,
        vulnerability_context: Optional[str] = None
    ) -> Dict:
        """
        Judge a single vulnerability finding

        Args:
            code: Source code being analyzed
            finding: Vulnerability finding from detector
            vulnerability_context: Optional context about expected vulnerabilities

        Returns:
            Judgment with: is_true_positive, confidence, reasoning
        """
        prompt = f"""You are a security expert judging vulnerability findings. Be precise about exploitability.

FINDING TO JUDGE:
Type: {finding.get('type', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Location: {finding.get('location', 'Unknown')}
Description: {finding.get('description', 'Unknown')}
Impact: {finding.get('impact', 'Unknown')}

CODE CONTEXT:
```
{code[:3000]}
```

CRITICAL ANALYSIS REQUIREMENTS:

For deserialization/reflection vulnerabilities:
1. Is untrusted input reachable? (data flow)
2. Is there validation? (e.g., Throwable instanceof check)
3. Are mitigations SUFFICIENT or just PARTIAL?
4. What's the actual attack vector?
5. For gadget chains: Are there KNOWN exploitable gadgets available?
   - Throwable subclasses with RCE in constructor are EXTREMELY RARE
   - Most gadgets are NOT Throwable subclasses
   - Type validation (instanceof Throwable) blocks most gadgets
   - Only known example: ClassPathXmlApplicationContext (requires Spring)

CONFIDENCE ADJUSTMENT:
- If Throwable validation exists AND no known Throwable+RCE gadgets found: Lower confidence (0.5-0.7)
- If specific gadget exists and is likely on classpath: Higher confidence (0.8+)
- If untrusted input is blocked: Lower confidence
- If partial validation (type check only): Medium confidence (0.6-0.75)

TASK:
Determine if this is a TRUE POSITIVE (real exploitable vulnerability) or FALSE POSITIVE.

Respond ONLY as valid JSON with NO other text:
{{
  "is_true_positive": true or false,
  "confidence": 0.0 to 1.0,
  "reasoning": "<detailed explanation including gadget availability analysis>",
  "severity_assessment": "CRITICAL|HIGH|MEDIUM|LOW|NOT_A_BUG",
  "gadget_analysis": "<what gadgets would be needed? are they Throwable? are they likely available?>"
}}"""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=500,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            result_text = message.content[0].text.strip()

            # Parse JSON response
            try:
                judgment = json.loads(result_text)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                import re
                json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
                if json_match:
                    try:
                        judgment = json.loads(json_match.group())
                    except:
                        return {
                            "is_true_positive": None,
                            "confidence": 0,
                            "reasoning": f"Failed to parse JSON: {result_text[:200]}",
                            "severity_assessment": "UNKNOWN"
                        }
                else:
                    return {
                        "is_true_positive": None,
                        "confidence": 0,
                        "reasoning": f"No JSON found in response: {result_text[:200]}",
                        "severity_assessment": "UNKNOWN"
                    }

            return {
                "is_true_positive": judgment.get("is_true_positive"),
                "confidence": judgment.get("confidence", 0),
                "reasoning": judgment.get("reasoning", ""),
                "severity_assessment": judgment.get("severity_assessment", "UNKNOWN")
            }

        except Exception as e:
            return {
                "is_true_positive": None,
                "confidence": 0,
                "reasoning": f"Judge error: {str(e)}",
                "severity_assessment": "ERROR"
            }

    def judge_batch_parallel(
        self,
        code_snippets: Dict[str, str],
        findings: List[Dict],
        callback=None
    ) -> Dict[str, Dict]:
        """
        Judge multiple findings in parallel using ThreadPoolExecutor

        Args:
            code_snippets: Dict of {finding_id: code}
            findings: List of findings to judge
            callback: Optional callback function for progress updates

        Returns:
            Dict of {finding_id: judgment}
        """
        import concurrent.futures
        
        judgments = {}
        futures = {}

        # Submit all tasks in parallel
        for finding in findings:
            finding_id = finding.get('id', 'unknown')
            code = code_snippets.get(finding_id, "")

            future = self.executor.submit(self.judge_finding, code, finding)
            futures[finding_id] = future

        # Collect results as they complete
        completed = 0
        for finding_id, future in futures.items():
            try:
                judgment = future.result(timeout=30)
                judgments[finding_id] = judgment
                completed += 1

                if callback:
                    callback(finding_id, judgment, completed, len(futures))
            except concurrent.futures.TimeoutError:
                judgments[finding_id] = {
                    "is_true_positive": None,
                    "confidence": 0,
                    "reasoning": "Judge timeout (>30s)",
                    "severity_assessment": "TIMEOUT"
                }
                completed += 1
                if callback:
                    callback(finding_id, judgments[finding_id], completed, len(futures))
            except Exception as e:
                judgments[finding_id] = {
                    "is_true_positive": None,
                    "confidence": 0,
                    "reasoning": f"Judge error: {str(e)}",
                    "severity_assessment": "ERROR"
                }
                completed += 1
                if callback:
                    callback(finding_id, judgments[finding_id], completed, len(futures))

        return judgments
