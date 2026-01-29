"""
LLM Judge for Benchmark Evaluation

Uses OpenAI GPT-4o as the ground truth judge to evaluate whether:
1. Detected vulnerabilities are TRUE POSITIVES (real issues)
2. Detected vulnerabilities are FALSE POSITIVES (not real issues)
3. Missed vulnerabilities are FALSE NEGATIVES (should have been detected)

This replaces manual ground truth labeling.
"""

import os
import json
import re
from typing import List, Dict, Optional, Tuple
from openai import OpenAI

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


class LLMJudge:
    """Uses GPT-4o to judge vulnerability findings"""

    def __init__(self, model: str = "gpt-4o"):
        self.model = model

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
        prompt = f"""You are a security expert judging vulnerability findings.

FINDING TO JUDGE:
Type: {finding.get('type', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
CWE: {finding.get('cwe', 'Unknown')}
Location: {finding.get('location', 'Unknown')}
Description: {finding.get('description', 'Unknown')}
Impact: {finding.get('impact', 'Unknown')}

CODE CONTEXT:
```
{code[:2000]}
```

TASK:
Determine if this is a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE.

Consider:
1. Is the vulnerable code pattern actually present?
2. Is the code actually exploitable?
3. Are there mitigations/validations that prevent exploitation?
4. Is this a real security issue or a false alarm?

Respond ONLY as valid JSON:
{{
  "is_true_positive": true or false,
  "confidence": 0.0 to 1.0,
  "reasoning": "<detailed explanation of judgment>",
  "severity_assessment": "CRITICAL|HIGH|MEDIUM|LOW|NOT_A_BUG"
}}"""

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security researcher. Always respond with valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                max_tokens=1000
            )

            result_text = response.choices[0].message.content.strip()

            # Parse JSON response
            try:
                judgment = json.loads(result_text)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
                if json_match:
                    judgment = json.loads(json_match.group())
                else:
                    return {
                        "is_true_positive": None,
                        "confidence": 0,
                        "reasoning": f"Failed to parse response: {result_text[:200]}",
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

    def judge_batch(
        self,
        code_snippets: Dict[str, str],
        findings: List[Dict]
    ) -> Dict[str, Dict]:
        """
        Judge multiple findings for different code snippets

        Args:
            code_snippets: Dict of {finding_id: code}
            findings: List of findings to judge

        Returns:
            Dict of {finding_id: judgment}
        """
        judgments = {}

        for finding in findings:
            finding_id = finding.get('id', 'unknown')
            code = code_snippets.get(finding_id, "")

            judgment = self.judge_finding(code, finding)
            judgments[finding_id] = judgment

            print(f"  Judged {finding_id}: {judgment['is_true_positive']} (confidence: {judgment['confidence']})")

        return judgments

    def judge_missed_vulnerability(
        self,
        code: str,
        vulnerability_description: str
    ) -> Dict:
        """
        Judge whether a missed vulnerability should have been detected

        Args:
            code: Source code that was analyzed
            vulnerability_description: Description of vulnerability that wasn't found

        Returns:
            Judgment about whether detection was missed
        """
        prompt = f"""You are a security expert evaluating a false negative.

CODE ANALYZED:
```
{code[:2000]}
```

VULNERABILITY THAT WASN'T DETECTED:
{vulnerability_description}

TASK:
Determine if this vulnerability ACTUALLY EXISTS in the code and SHOULD have been detected.

Consider:
1. Does the vulnerable pattern actually exist in this code?
2. Is it exploitable?
3. Is it a real security issue?
4. Would a competent security tool be expected to find it?

Respond ONLY as valid JSON:
{{
  "vulnerability_exists": true or false,
  "should_have_been_detected": true or false,
  "confidence": 0.0 to 1.0,
  "reasoning": "<explanation>"
}}"""

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security researcher. Respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=500
            )

            result_text = response.choices[0].message.content.strip()
            judgment = json.loads(result_text)

            return {
                "vulnerability_exists": judgment.get("vulnerability_exists"),
                "should_have_been_detected": judgment.get("should_have_been_detected"),
                "confidence": judgment.get("confidence", 0),
                "reasoning": judgment.get("reasoning", "")
            }

        except Exception as e:
            return {
                "vulnerability_exists": None,
                "should_have_been_detected": None,
                "confidence": 0,
                "reasoning": f"Judge error: {str(e)}"
            }


class BenchmarkWithJudge:
    """Run benchmark evaluation with LLM judge as ground truth"""

    def __init__(self):
        self.judge = LLMJudge()

    def evaluate_detector_findings(
        self,
        detector_name: str,
        findings: List[Dict],
        code_snippets: Dict[str, str]
    ) -> Dict:
        """
        Evaluate detector findings using LLM judge

        Args:
            detector_name: Name of detector (e.g., "pattern_matching", "gpt_analysis")
            findings: List of findings from detector
            code_snippets: Dict of code snippets for context

        Returns:
            Evaluation metrics: TP, FP, FN, precision, recall, etc.
        """
        print(f"\n📊 Evaluating {detector_name} with LLM Judge")
        print(f"   Total findings: {len(findings)}")

        judgments = self.judge.judge_batch(code_snippets, findings)

        # Calculate metrics
        true_positives = sum(1 for j in judgments.values() if j.get("is_true_positive") == True)
        false_positives = sum(1 for j in judgments.values() if j.get("is_true_positive") == False)
        uncertain = sum(1 for j in judgments.values() if j.get("is_true_positive") is None)

        total_judged = len(judgments)
        if total_judged == 0:
            return {"error": "No findings to evaluate"}

        precision = true_positives / total_judged if total_judged > 0 else 0
        avg_confidence = sum(j.get("confidence", 0) for j in judgments.values()) / total_judged

        evaluation = {
            "detector": detector_name,
            "total_findings": len(findings),
            "true_positives": true_positives,
            "false_positives": false_positives,
            "uncertain": uncertain,
            "precision": precision,
            "avg_confidence": avg_confidence,
            "judgments": judgments
        }

        print(f"   ✅ True Positives: {true_positives}")
        print(f"   ❌ False Positives: {false_positives}")
        print(f"   ❓ Uncertain: {uncertain}")
        print(f"   📈 Precision: {precision:.2%}")
        print(f"   🎯 Avg Confidence: {avg_confidence:.2f}")

        return evaluation

    def compare_detectors(
        self,
        detectors: Dict[str, List[Dict]],
        code_snippets: Dict[str, str]
    ) -> Dict:
        """
        Compare multiple detectors using LLM judge

        Args:
            detectors: Dict of {detector_name: findings}
            code_snippets: Code context for all findings

        Returns:
            Comparison results
        """
        results = {}

        for detector_name, findings in detectors.items():
            results[detector_name] = self.evaluate_detector_findings(
                detector_name,
                findings,
                code_snippets
            )

        # Summary comparison
        print("\n" + "=" * 80)
        print("COMPARISON SUMMARY")
        print("=" * 80)

        comparison_table = []
        for detector_name, metrics in results.items():
            if "error" not in metrics:
                comparison_table.append({
                    "Detector": detector_name,
                    "Findings": metrics["total_findings"],
                    "TP": metrics["true_positives"],
                    "FP": metrics["false_positives"],
                    "Precision": f"{metrics['precision']:.2%}",
                    "Confidence": f"{metrics['avg_confidence']:.2f}"
                })

        # Print table
        if comparison_table:
            headers = comparison_table[0].keys()
            print("\n" + " | ".join(headers))
            print("-" * (len(" | ".join(headers))))
            for row in comparison_table:
                print(" | ".join(str(row[h]) for h in headers))

        return results


def demo_judge():
    """Demo: Judge some example findings"""
    judge = LLMJudge()

    # Example code
    code = """
void process_data(char* input) {
    char buffer[256];
    strcpy(buffer, input);  // Buffer overflow vulnerability
    printf(buffer);         // Format string vulnerability
}
"""

    # Example finding
    finding = {
        "type": "Buffer Overflow",
        "severity": "CRITICAL",
        "cwe": "CWE-120",
        "location": "process_data function, line 3",
        "description": "Unbounded strcpy() call with user input",
        "impact": "RCE via stack overflow"
    }

    print("🔍 Judging finding...")
    judgment = judge.judge_finding(code, finding)

    print(f"✓ Is True Positive: {judgment['is_true_positive']}")
    print(f"✓ Confidence: {judgment['confidence']}")
    print(f"✓ Severity Assessment: {judgment['severity_assessment']}")
    print(f"✓ Reasoning: {judgment['reasoning']}")


if __name__ == "__main__":
    demo_judge()
