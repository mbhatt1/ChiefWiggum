# SEC-Bench Benchmark - Setup & Deployment Guide

Complete infrastructure for running ChiefWiggum vs Claude evaluation against SEC-bench vulnerabilities.

## What's Included

```
benchmark/
├── secbench_runner.py          # Main evaluation engine
├── analysis.py                 # Results analysis & visualization
├── run_benchmark.sh            # Orchestration script
├── configs/
│   └── default.json            # Evaluation configuration
├── sandbox/
│   ├── Dockerfile              # Isolated evaluation environment
│   └── docker-compose.yml      # Multi-container orchestration
├── data/                       # Local datasets
├── results/                    # Evaluation outputs
├── requirements.txt            # Python dependencies
├── README.md                   # Full documentation
├── QUICKSTART.md              # 5-minute setup
└── SETUP.md                   # This file
```

## Prerequisites

### System Requirements
- **CPU**: 2+ cores recommended
- **Memory**: 2GB minimum (4GB+ for full 600-vulnerability run)
- **Disk**: 2-3GB free (for HuggingFace dataset)
- **Network**: Required for HuggingFace/Anthropic API

### Software
- Python 3.9+
- pip (Python package manager)
- Docker (optional, for sandbox isolation)
- Docker Compose (optional, for multi-service setup)

### API Credentials
- **Anthropic API Key**: Required for Claude analysis
  - Get from: https://console.anthropic.com/account/keys
  - Free tier: $5 credit, rate-limited
  - Pricing: ~$0.50 for 100-vuln run, ~$250 for 600-vuln run

## Installation Steps

### Step 1: Install Dependencies

```bash
# Navigate to repo
cd /path/to/chiefwiggum-loop

# Install Python packages
pip install -r benchmark/requirements.txt

# Verify installation
python3 -c "import anthropic; print('✓ Anthropic SDK installed')"
python3 -c "from datasets import load_dataset; print('✓ HuggingFace datasets installed')"
```

### Step 2: Configure API Key

**Option A: Environment Variable (recommended)**
```bash
export ANTHROPIC_API_KEY="sk-ant-xxxxxxxxxxxxx"
```

**Option B: .env File**
```bash
cat > .env << EOF
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx
EOF

# Load in shell
source .env
```

**Option C: Docker Secret**
```bash
# Create Docker secret for secure handling
docker secret create anthropic_key -
# Enter API key, press Ctrl+D
```

### Step 3: Verify Setup

```bash
# Test ChiefWiggum installation
python3 -m chiefwiggum --help

# Test Claude API access
python3 << 'EOF'
from anthropic import Anthropic

client = Anthropic()
try:
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=100,
        messages=[{"role": "user", "content": "Say 'OK'"}]
    )
    print("✓ Anthropic API working")
except Exception as e:
    print(f"✗ API Error: {e}")
EOF

# Check datasets library
python3 << 'EOF'
try:
    from datasets import load_dataset
    print("✓ HuggingFace datasets ready")
except Exception as e:
    print(f"⚠ Note: {e}")
EOF
```

## Configuration

### Main Config: `benchmark/configs/default.json`

```json
{
  "benchmark_name": "SEC-Bench Full Evaluation",
  "dataset_source": "synthetic|local|huggingface",
  "dataset_limit": 100,
  "tools": ["chiefwiggum", "claude-haiku", "claude-opus"],
  "evaluation_metrics": [
    "detection_rate",
    "true_positive_rate",
    "false_positive_rate",
    "patch_quality",
    "analysis_time",
    "cost_estimate"
  ]
}
```

### Custom Configuration

Create your own config:

```bash
cat > benchmark/configs/custom.json << 'EOF'
{
  "benchmark_name": "Small Test Run",
  "dataset_source": "synthetic",
  "dataset_limit": 50,
  "tools": ["chiefwiggum", "claude-haiku"],
  "api_config": {
    "rate_limit_qps": 5
  }
}
EOF

# Use it:
./benchmark/run_benchmark.sh --config benchmark/configs/custom.json
```

## Running Benchmarks

### Option 1: Bash Script (Easiest)

```bash
# Quick test (5 min, 100 vulns, synthetic data)
./benchmark/run_benchmark.sh

# Full benchmark (1-2 hours, 600 vulns, real data)
DATASET_SOURCE=huggingface DATASET_LIMIT=600 ./benchmark/run_benchmark.sh

# Custom config
./benchmark/run_benchmark.sh --config benchmark/configs/custom.json
```

### Option 2: Python CLI (Direct)

```bash
# Quick test
python benchmark/secbench_runner.py \
  --dataset synthetic \
  --limit 100 \
  --tools chiefwiggum claude-haiku

# Full run with HuggingFace
python benchmark/secbench_runner.py \
  --dataset huggingface \
  --limit 600 \
  --tools chiefwiggum claude-haiku claude-opus \
  --config benchmark/configs/default.json
```

### Option 3: Docker (Isolated)

```bash
# Build sandbox image
docker build -f benchmark/sandbox/Dockerfile -t secbench-eval .

# Run quick test
docker run -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd)/benchmark/results:/secbench/benchmark/results \
  secbench-eval \
  python benchmark/secbench_runner.py --dataset synthetic --limit 100

# Run full benchmark
docker run -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd)/benchmark/results:/secbench/benchmark/results \
  secbench-eval \
  python benchmark/secbench_runner.py --dataset huggingface --limit 600
```

### Option 4: Docker Compose (Complete Stack)

```bash
# Configure environment
cat > benchmark/.env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx
DATASET_SOURCE=synthetic
DATASET_LIMIT=100
TOOLS=chiefwiggum claude-haiku claude-opus
EOF

# Run
cd benchmark
docker-compose up

# Results automatically in: benchmark/results/
```

## Dataset Management

### Synthetic Data (Default)
- No network needed
- Fast to run
- Limited to ~100 vulnerabilities
- Good for testing

```bash
DATASET_SOURCE=synthetic DATASET_LIMIT=100 ./benchmark/run_benchmark.sh
```

### Local Dataset
- Load from `benchmark/data/secbench.json`
- Upload your own vulnerability data
- Useful for internal vulnerability datasets

```bash
# Format: JSON with vulnerabilities array
python benchmark/secbench_runner.py --dataset local --limit 600
```

### HuggingFace Dataset (Full SEC-Bench)
- Real 600 CVE/OSS-Fuzz vulnerabilities
- ~2GB download (first time)
- 34 open-source projects
- Official benchmark

```bash
DATASET_SOURCE=huggingface DATASET_LIMIT=600 ./benchmark/run_benchmark.sh
```

## Results & Analysis

### Results Location
```
benchmark/results/
└── evaluation_2026-01-27T22-30-45.123456.json
```

### Quick Summary
```bash
# Latest results
python benchmark/analysis.py benchmark/results/*.json --summary
```

### Detailed Analysis
```bash
# Compare tools
python benchmark/analysis.py benchmark/results/latest.json --compare

# Hybrid strategy analysis
python benchmark/analysis.py benchmark/results/latest.json --hybrid

# Vulnerability breakdown
python benchmark/analysis.py benchmark/results/latest.json --breakdown

# All analyses
python benchmark/analysis.py benchmark/results/latest.json --all
```

### Results Format

```json
{
  "timestamp": "2026-01-27T22:30:45.123456",
  "dataset_size": 600,
  "metrics": {
    "chiefwiggum": {
      "detection_rate": 81.0,
      "true_positive_rate": 86.4,
      "false_positive_rate": 13.6,
      "avg_patch_quality": 63.2,
      "avg_detection_time": 0.12,
      "cost_estimate": 522.0
    },
    "claude-haiku": {
      "detection_rate": 72.5,
      "true_positive_rate": 88.3,
      ...
    },
    ...
  }
}
```

## Cost Estimation

### Single Tool Runs (600 vulnerabilities)

| Tool | Cost | Speed | Quality |
|------|------|-------|---------|
| ChiefWiggum | $0 | <1s/vuln | 63/100 |
| Claude Haiku | $300 | 2-5s/vuln | 75/100 |
| Claude Opus | $1500 | 3-8s/vuln | 79/100 |

### Hybrid Approach (600 vulnerabilities)

| Phase | Tool | Vulns | Cost | Time |
|-------|------|-------|------|------|
| Triage | ChiefWiggum | 600 | $0 | <10min |
| High-confidence | — | 200 | $0 | — |
| Escalate to Claude | Claude Opus | 400 | $1000 | ~1 hour |
| **Total** | — | 600 | **$1000** | **~1.5 hours** |

**Savings: 33% vs pure Claude, better quality than ChiefWiggum alone**

## Troubleshooting

### Problem: HuggingFace Download Fails

```bash
# Solution 1: Use synthetic data
DATASET_SOURCE=synthetic ./benchmark/run_benchmark.sh

# Solution 2: Manual download
python3 << 'EOF'
from datasets import load_dataset
dataset = load_dataset("SEC-bench/SEC-bench")
# Will cache in ~/.cache/huggingface/
EOF

# Solution 3: Network retry
export HF_DATASETS_OFFLINE=0
python benchmark/secbench_runner.py --dataset huggingface
```

### Problem: API Rate Limits

```bash
# Solution 1: Smaller batch
DATASET_LIMIT=50 ./benchmark/run_benchmark.sh

# Solution 2: Reduce tools
--tools chiefwiggum claude-haiku  # Skip Opus

# Solution 3: Add delays
# Edit secbench_runner.py, add: time.sleep(0.5)
```

### Problem: Out of Memory

```bash
# Solution 1: Reduce dataset
DATASET_LIMIT=100 ./benchmark/run_benchmark.sh

# Solution 2: Use Docker with memory limits
docker run --memory=2g -e ANTHROPIC_API_KEY=$KEY secbench-eval

# Solution 3: Stream processing
# Modify secbench_runner.py for batch processing
```

### Problem: ANTHROPIC_API_KEY Not Found

```bash
# Check if set
echo $ANTHROPIC_API_KEY

# Set it
export ANTHROPIC_API_KEY="sk-ant-xxxxx"

# Test API access
python3 -c "from anthropic import Anthropic; Anthropic().messages.create(model='claude-haiku-4-5-20251001', max_tokens=1, messages=[{'role':'user','content':'hi'}])"
```

## Integration with CI/CD

### GitHub Actions

```yaml
name: SEC-Bench Benchmark

on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly at 2 AM UTC
  workflow_dispatch:

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -r benchmark/requirements.txt
      - name: Run benchmark
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          DATASET_LIMIT=100 ./benchmark/run_benchmark.sh
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: benchmark/results/
```

## Next Steps

1. **Quick Test**: `./benchmark/run_benchmark.sh`
2. **Full Benchmark**: `DATASET_SOURCE=huggingface DATASET_LIMIT=600 ./benchmark/run_benchmark.sh`
3. **Analyze**: `python benchmark/analysis.py benchmark/results/*.json --all`
4. **Deploy**: Integrate into security pipeline per recommendations

---

For more information, see:
- [Detailed README](README.md)
- [Quick Start](QUICKSTART.md)
- [SEC-Bench Official](https://sec-bench.github.io/)
