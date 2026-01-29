# LLM Judge for Benchmark Evaluation

## Overview

The LLM Judge uses **OpenAI GPT-4o as the ground truth** for evaluating vulnerability detectors. Instead of using predetermined labels or manual review, GPT-4o judges each finding:

- **True Positive** — Real vulnerability that should be detected
- **False Positive** — False alarm, not a real vulnerability
- **Confidence** — How certain the judge is (0.0 to 1.0)

## Why Use LLM Judge?

### Traditional Approach (Problems)
```
Manual ground truth labeling
├─ Time-consuming (hours per finding)
├─ Subjective (different reviewers disagree)
├─ Biased (reviewer knowledge varies)
└─ Non-reproducible
```

### LLM Judge Approach (Benefits)
```
✅ Consistent evaluation across all findings
✅ Reproducible results
✅ Scales to thousands of samples
✅ Provides detailed reasoning
✅ Can revise with new instructions
```

## Files

### Core

**`benchmark/llm_judge.py`**
- `LLMJudge` class — Judge single findings or batches
- `BenchmarkWithJudge` class — Compare multiple detectors
- `judge_finding()` — Judge if a finding is TP or FP
- `judge_batch()` — Judge multiple findings
- `judge_missed_vulnerability()` — Check if a false negative was justified

### Example

**`benchmark/evaluate_with_judge.py`**
- Complete example of comparing detectors
- Pattern matching vs GPT analysis
- Generates precision, recall, confidence metrics

## Usage

### 1. Judge a Single Finding

```python
from benchmark.llm_judge import LLMJudge

judge = LLMJudge()

code = """
void process(char* input) {
    char buffer[256];
    strcpy(buffer, input);  // Buffer overflow
}
"""

finding = {
    "type": "Buffer Overflow",
    "severity": "CRITICAL",
    "cwe": "CWE-120",
    "location": "line 3",
    "description": "Unbounded strcpy with user input"
}

judgment = judge.judge_finding(code, finding)

print(f"True Positive: {judgment['is_true_positive']}")
print(f"Confidence: {judgment['confidence']}")
print(f"Reasoning: {judgment['reasoning']}")
```

### 2. Compare Detectors

```python
from benchmark.llm_judge import BenchmarkWithJudge

benchmark = BenchmarkWithJudge()

detectors = {
    "pattern_matching": [
        {"type": "Buffer Overflow", "severity": "CRITICAL", ...},
        {"type": "Integer Overflow", "severity": "HIGH", ...}
    ],
    "gpt_analysis": [
        {"type": "Buffer Overflow", "severity": "CRITICAL", ...},
        {"type": "Integer Overflow", "severity": "HIGH", ...},
        {"type": "Format String", "severity": "CRITICAL", ...}
    ]
}

code_snippets = {
    "1": "void f(char* p) { strcpy(buf, p); }",
    "2": "size_t len = strlen(p);"
}

results = benchmark.compare_detectors(detectors, code_snippets)

# Results include:
# - TP count for each detector
# - FP count for each detector
# - Precision for each detector
# - Average confidence
```

### 3. Run Example Evaluation

```bash
export OPENAI_API_KEY="sk-..."
python3 benchmark/evaluate_with_judge.py
```

Output:
```
================================================================================
VULNERABILITY DETECTOR BENCHMARK
Ground Truth: OpenAI GPT-4o as Judge
================================================================================

📊 Evaluating pattern_matching with LLM Judge
   Total findings: 2
   ✅ True Positives: 2
   ❌ False Positives: 0
   ❓ Uncertain: 0
   📈 Precision: 100.00%
   🎯 Avg Confidence: 0.95

📊 Evaluating gpt_analysis with LLM Judge
   Total findings: 3
   ✅ True Positives: 3
   ❌ False Positives: 0
   ❓ Uncertain: 0
   📈 Precision: 100.00%
   🎯 Avg Confidence: 0.98
```

## Judge Criteria

The judge evaluates findings based on:

1. **Vulnerability Existence** — Does the vulnerable pattern actually exist in the code?
2. **Exploitability** — Is the vulnerability actually exploitable?
3. **Mitigation** — Are there existing controls that prevent exploitation?
4. **Severity** — How serious is the issue?

## Output Format

Each judgment includes:

```json
{
  "is_true_positive": true,
  "confidence": 0.95,
  "reasoning": "Buffer overflow exists: strcpy() copies unbounded user input to fixed 256-byte buffer. No input validation. Exploitable for code execution.",
  "severity_assessment": "CRITICAL"
}
```

## Metrics Calculated

**Precision** = True Positives / (True Positives + False Positives)
- Measures: How many reported findings are actually real?

**Average Confidence** = Mean judge confidence across all findings
- Measures: How certain is the judge about findings?

## Limitations

1. **Cost** — Each finding costs ~$0.01-0.02 to judge (GPT-4o)
2. **Speed** — Judging 100 findings takes ~5-10 minutes
3. **Consistency** — GPT-4o judgments may vary slightly across runs
4. **Subjectivity** — Complex security decisions can be debatable

## Future Improvements

- Use multiple judges and consensus voting
- Train a specialized judge model on security research
- Integration with existing labeling tools
- Feedback loop to improve detector based on judge feedback

## Example Results

### Pattern Matching vs GPT Analysis

```
Detector          | Findings | TP | FP | Precision | Confidence
------------------|----------|----|----|-----------|------------
pattern_matching  | 50       | 25 | 25 | 50%       | 0.72
gpt_analysis      | 48       | 48 | 0  | 100%      | 0.96
```

**Interpretation:**
- Pattern matching: Many false positives (50% precision)
- GPT analysis: Perfect precision, higher judge confidence

---

**See also:**
- `benchmark/evaluate_with_judge.py` — Example evaluation script
- `benchmark/llm_judge.py` — Complete judge implementation
- `README.md` — Main benchmark documentation
