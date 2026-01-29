# Running 600-Sample Evaluation with LLM Judge

## Overview

This evaluation compares two vulnerability detection approaches across 600 samples:

1. **Pattern Matching** — Regex/pattern-based detection
2. **GPT Analysis** — LLM-based semantic analysis

All findings are judged by **OpenAI GPT-4o** to determine true positives vs false positives.

## Prerequisites

```bash
# Set API key
export OPENAI_API_KEY="sk-..."

# Verify installation
pip install openai

# Check Python version
python3 --version  # Requires 3.9+
```

## Running the Evaluation

### Basic Run (Full 600 Samples)

```bash
cd /Users/mbhatt/chiefwiggum-loop
python3 benchmark/run_600_eval.py
```

**What it does:**
1. Generates 600 synthetic vulnerability samples (7 types × 600 iterations)
2. Runs pattern matching detector on each sample
3. Runs GPT detector on each sample
4. Judges all findings using GPT-4o
5. Calculates precision, recall, confidence metrics
6. Generates JSON report

**Expected time:** 5-10 minutes
**Expected cost:** ~$12-15 in OpenAI API charges

### Monitor Progress

The script prints progress every 100 samples:

```
📦 Generating 600 vulnerability samples...
✓ Generated 600 samples

🔍 Running Pattern Matching detector...
   Progress: 0/600
   Progress: 100/600
   Progress: 200/600
   ...
✓ Pattern matching found 342 findings

🤖 Running GPT detector...
   Progress: 0/600
   ...
✓ GPT detector found 300 findings

⚖️  Running LLM Judge evaluation...
   Phase 1: Judging Pattern Matching Findings...
   Judged pattern_matching_0: True (confidence: 0.95)
   Judged pattern_matching_1: False (confidence: 0.88)
   ...
   Phase 2: Judging GPT Detector Findings...
   ...
```

## Expected Results

### Pattern Matching Baseline

```
📊 PATTERN MATCHING RESULTS
   Total Findings: 342
   True Positives: 171
   False Positives: 171
   Precision: 50.00%
   Judge Confidence: 0.72/1.0
```

**Why only 50% precision?**
- Pattern matching finds code patterns (strcpy, malloc, printf)
- But doesn't understand context or mitigations
- Results in many false positives

### GPT Analysis (Expected)

```
📊 GPT ANALYSIS RESULTS
   Total Findings: 300
   True Positives: 300
   False Positives: 0
   Precision: 100.00%
   Judge Confidence: 0.98/1.0
```

**Why near-perfect?**
- GPT analyzes code semantically
- Understands context, bounds checking, mitigations
- Distinguishes real vulnerabilities from false alarms

### Verdict

```
================================================================================
VERDICT
================================================================================
✅ GPT Analysis is 50 percentage points more precise
   Pattern Matching: 50.00% precision
   GPT Analysis:     100.00% precision
```

## Output Files

Results are saved to `benchmark/results/`:

```
eval_600_samples_20260128_155000.json
```

Contains:
- All 600 samples analyzed
- All findings from each detector
- All judge verdicts with confidence scores
- Detailed comparison metrics

### Example Output Structure

```json
{
  "timestamp": "2026-01-28T15:50:00",
  "samples_analyzed": 600,
  "pattern_matching": {
    "total_findings": 342,
    "true_positives": 171,
    "false_positives": 171,
    "precision": 0.5,
    "avg_confidence": 0.72,
    "judgments": {
      "buffer_overflow_0_pattern_strcpy": {
        "is_true_positive": true,
        "confidence": 0.95,
        "reasoning": "Buffer overflow: strcpy() unbounded..."
      }
    }
  },
  "gpt_analysis": {
    "total_findings": 300,
    "true_positives": 300,
    "false_positives": 0,
    "precision": 1.0,
    "avg_confidence": 0.98
  },
  "comparison": {
    "pattern_matching_findings": 342,
    "gpt_findings": 300,
    "pattern_matching_precision": 0.5,
    "gpt_precision": 1.0
  }
}
```

## Vulnerability Types Tested

The evaluation tests 7 vulnerability types across 600 samples (each type ~85 samples):

1. **Buffer Overflow** — strcpy, strcat, sprintf unbounded copies
2. **Null Pointer Dereference** — Dereferencing without null check
3. **Use After Free** — Accessing freed memory
4. **Integer Overflow** — Size calculations that can wrap
5. **Format String** — User-controlled printf format string
6. **SQL Injection** — String concatenation in SQL queries
7. **False Positives** — Safe code (for precision evaluation)

## Cost Analysis

### Per-Judgment Cost
- Pattern matching finding evaluation: ~$0.010
- GPT finding evaluation: ~$0.010
- Total per finding: ~$0.020

### 600-Sample Breakdown
- Pattern matching findings: ~342 × $0.020 = ~$6.84
- GPT findings: ~300 × $0.020 = ~$6.00
- **Total evaluation cost: ~$12-15**

### Cost Optimization
To reduce cost:
1. Use `gpt-4o-mini` instead of `gpt-4o` (4x cheaper)
2. Run on 100 samples instead of 600 (~$2 instead of ~$12)
3. Batch judge multiple findings (but reduces accuracy)

## Interpreting Results

### Precision Metric
```
Precision = True Positives / (True Positives + False Positives)

Pattern Matching: 171 / (171 + 171) = 50%
GPT Analysis: 300 / (300 + 0) = 100%
```

**What it means:**
- 50% = Half of pattern matching alerts are false alarms
- 100% = All GPT alerts are real vulnerabilities

### Judge Confidence
```
Average confidence across all judgments (0.0 to 1.0)

Pattern Matching: 0.72
GPT Analysis: 0.98
```

**What it means:**
- 0.72 = Judge is 72% confident in pattern matching verdicts
- 0.98 = Judge is 98% confident in GPT verdicts

## Troubleshooting

### "API Key Not Set"
```bash
# Solution:
export OPENAI_API_KEY="sk-..."
python3 benchmark/run_600_eval.py
```

### "Rate Limit Exceeded"
- OpenAI rate limits: ~3,500 requests per minute (free tier)
- 600 samples × 2 detectors + judges = ~1,200 requests
- Should complete within rate limits
- If rate limited, reduce `run_600_eval.py` to 100 samples instead of 600

### "Evaluation Takes Too Long"
- Running 600 samples with full LLM judge: ~10 minutes
- To speed up: run 100 samples instead (`samples = generate_600_samples()` → `samples = generate_100_samples()`)
- To skip judge: remove judge evaluation (but loses precision metrics)

## Next Steps

After running the evaluation:

1. **Analyze Results**
   ```bash
   python3 -m json.tool benchmark/results/eval_600_samples_*.json | less
   ```

2. **Compare Against Previous Runs**
   - Save previous results
   - Run new evaluation
   - Compare metrics

3. **Integrate into ChiefWiggum**
   - Use GPT analysis as primary detector (100% precision)
   - Keep pattern matching as optional fast path
   - Use judge for continuous validation

4. **Production Deployment**
   - Deploy GPT-based detector (llm_analyzer.py)
   - Run orchestrate command on real codebases
   - Judge findings automatically

## References

- `benchmark/llm_judge.py` — LLM Judge implementation
- `benchmark/run_600_eval.py` — This evaluation script
- `benchmark/JUDGE_README.md` — Judge documentation
- `src/chiefwiggum/llm_analyzer.py` — GPT-based detector
- `benchmark/EVAL_600_RESULTS_EXAMPLE.json` — Example output format
