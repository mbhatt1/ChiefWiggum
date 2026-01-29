#!/usr/bin/env python3
"""
Evaluate vulnerability detectors using LLM Judge as ground truth

Usage:
    python benchmark/evaluate_with_judge.py --detector pattern_matching,gpt_analysis
"""

import argparse
import json
import sys
from pathlib import Path
from llm_judge import BenchmarkWithJudge


def run_evaluation(detectors: list, code_samples: int = 10):
    """
    Run evaluation with LLM judge

    Args:
        detectors: List of detector names to compare
        code_samples: Number of code samples to evaluate
    """
    print("=" * 80)
    print("VULNERABILITY DETECTOR BENCHMARK")
    print("Ground Truth: OpenAI GPT-4o as Judge")
    print("=" * 80)

    # Example findings from different detectors
    # In real usage, these would come from actual detector runs

    example_findings = {
        "pattern_matching": [
            {
                "id": "pattern_1",
                "type": "Buffer Overflow",
                "severity": "CRITICAL",
                "cwe": "CWE-120",
                "location": "strcpy(buffer, input)",
                "description": "Unbounded string copy",
                "impact": "RCE via stack overflow"
            },
            {
                "id": "pattern_2",
                "type": "Integer Overflow",
                "severity": "HIGH",
                "cwe": "CWE-190",
                "location": "size_t len = strlen(input)",
                "description": "Potential integer wrap",
                "impact": "Memory corruption"
            }
        ],
        "gpt_analysis": [
            {
                "id": "gpt_1",
                "type": "Buffer Overflow",
                "severity": "CRITICAL",
                "cwe": "CWE-120",
                "location": "strcpy(buffer, input)",
                "description": "Unbounded string copy with user input",
                "impact": "RCE via stack overflow"
            },
            {
                "id": "gpt_2",
                "type": "Integer Overflow",
                "severity": "HIGH",
                "cwe": "CWE-190",
                "location": "size_t len = strlen(input)",
                "description": "Potential integer wrap on 32-bit systems",
                "impact": "Memory corruption"
            },
            {
                "id": "gpt_3",
                "type": "Format String",
                "severity": "CRITICAL",
                "cwe": "CWE-134",
                "location": "printf(buffer)",
                "description": "User-controlled format string",
                "impact": "Information disclosure and code execution"
            }
        ]
    }

    # Example code snippets for context
    code_snippets = {
        "pattern_1": """
void process_data(char* input) {
    char buffer[256];
    strcpy(buffer, input);  // Line 3: Buffer overflow
    printf("%s\\n", buffer);
}
""",
        "pattern_2": """
void allocate_buffer(char* input) {
    size_t len = strlen(input);  // Potential integer wrap
    char* buf = malloc(len);
    if (!buf) return NULL;
    return buf;
}
""",
        "gpt_1": """
void process_data(char* input) {
    char buffer[256];
    strcpy(buffer, input);  // Buffer overflow
    printf("%s\\n", buffer);
}
""",
        "gpt_2": """
void allocate_buffer(char* input) {
    size_t len = strlen(input);
    char* buf = malloc(len);
    if (!buf) return NULL;
    return buf;
}
""",
        "gpt_3": """
void process_data(char* input) {
    char buffer[256];
    strcpy(buffer, input);
    printf(buffer);  // Format string vulnerability - line 4
}
"""
    }

    # Initialize benchmark with judge
    benchmark = BenchmarkWithJudge()

    # Evaluate each detector
    results = {}
    for detector_name in detectors:
        if detector_name in example_findings:
            results[detector_name] = benchmark.evaluate_detector_findings(
                detector_name,
                example_findings[detector_name],
                code_snippets
            )
        else:
            print(f"⚠️  Unknown detector: {detector_name}")

    # Generate comparison report
    print("\n" + "=" * 80)
    print("DETAILED FINDINGS BREAKDOWN")
    print("=" * 80)

    for detector_name, evaluation in results.items():
        if "error" not in evaluation:
            print(f"\n{detector_name.upper()}")
            print("-" * 80)
            print(f"Total Findings: {evaluation['total_findings']}")
            print(f"True Positives: {evaluation['true_positives']}")
            print(f"False Positives: {evaluation['false_positives']}")
            print(f"Precision: {evaluation['precision']:.2%}")
            print(f"Average Judge Confidence: {evaluation['avg_confidence']:.2f}/1.0")

            # Show per-finding judgments
            print("\nPer-Finding Judgments:")
            for finding_id, judgment in evaluation['judgments'].items():
                is_tp = "✅ TP" if judgment['is_true_positive'] else "❌ FP" if judgment['is_true_positive'] == False else "❓ UNCERTAIN"
                print(f"  {finding_id}: {is_tp} (confidence: {judgment['confidence']:.2f}, severity: {judgment['severity_assessment']})")

    # Save results
    results_file = Path("benchmark/results") / "judge_evaluation.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)

    with open(results_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n✅ Results saved to {results_file}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate detectors with LLM Judge")
    parser.add_argument(
        "--detector",
        default="pattern_matching,gpt_analysis",
        help="Comma-separated list of detectors to evaluate"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=10,
        help="Number of code samples to evaluate"
    )

    args = parser.parse_args()
    detectors = [d.strip() for d in args.detector.split(",")]

    results = run_evaluation(detectors, code_samples=args.samples)

    # Exit with status based on results
    sys.exit(0)
