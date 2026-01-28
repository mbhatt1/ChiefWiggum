#!/bin/bash
# SEC-Bench Evaluation Runner
# Orchestrates full benchmark evaluation across ChiefWiggum vs Claude

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DATASET_SOURCE="${DATASET_SOURCE:-synthetic}"
DATASET_LIMIT="${DATASET_LIMIT:-100}"
TOOLS="${TOOLS:-chiefwiggum claude-haiku claude-opus}"
CONFIG_FILE="${CONFIG_FILE:-benchmark/configs/default.json}"

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}SEC-Bench Full Evaluation Framework${NC}"
echo -e "${BLUE}ChiefWiggum vs Claude (Haiku/Opus)${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Step 1: Check Prerequisites
echo -e "${YELLOW}[1/5] Checking prerequisites...${NC}"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python 3 found${NC}"

if ! python3 -c "import anthropic" 2>/dev/null; then
    echo -e "${YELLOW}⚠ Installing dependencies...${NC}"
    pip3 install -q -r "$SCRIPT_DIR/requirements.txt"
    echo -e "${GREEN}✓ Dependencies installed${NC}"
fi

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${YELLOW}⚠ ANTHROPIC_API_KEY not set${NC}"
    echo "  Set with: export ANTHROPIC_API_KEY='sk-ant-...'"
    if [[ "$TOOLS" == *"claude"* ]]; then
        echo -e "${RED}✗ Claude tools require API key${NC}"
        exit 1
    fi
fi

# Step 2: Prepare environment
echo ""
echo -e "${YELLOW}[2/5] Preparing environment...${NC}"

mkdir -p "$SCRIPT_DIR/results"
mkdir -p "$SCRIPT_DIR/data"

if [ ! -f "$REPO_ROOT/$CONFIG_FILE" ]; then
    echo -e "${YELLOW}⚠ Config file not found: $CONFIG_FILE${NC}"
    echo "  Using default config..."
    CONFIG_FILE="benchmark/configs/default.json"
fi

echo -e "${GREEN}✓ Environment ready${NC}"

# Step 3: Load dataset
echo ""
echo -e "${YELLOW}[3/5] Loading dataset ($DATASET_SOURCE)...${NC}"

case $DATASET_SOURCE in
    synthetic)
        echo "  Using synthetic SEC-bench data (for testing)"
        ;;
    local)
        if [ ! -f "$SCRIPT_DIR/data/secbench.json" ]; then
            echo -e "${RED}✗ Local dataset not found: $SCRIPT_DIR/data/secbench.json${NC}"
            exit 1
        fi
        echo "  Loading from local file..."
        ;;
    huggingface)
        echo "  Loading from HuggingFace (requires network)..."
        echo "  Note: First run will download ~2GB dataset"
        ;;
esac

echo -e "${GREEN}✓ Dataset ready${NC}"

# Step 4: Run evaluation
echo ""
echo -e "${YELLOW}[4/5] Running evaluation...${NC}"
echo "  Dataset:      $DATASET_SOURCE"
echo "  Limit:        $DATASET_LIMIT vulnerabilities"
echo "  Tools:        $TOOLS"
echo "  Config:       $CONFIG_FILE"
echo ""

cd "$REPO_ROOT"

python3 benchmark/secbench_runner.py \
    --dataset "$DATASET_SOURCE" \
    --tools $TOOLS \
    --limit "$DATASET_LIMIT" \
    --config "$CONFIG_FILE"

RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo -e "${RED}✗ Evaluation failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Evaluation complete${NC}"

# Step 5: Display results
echo ""
echo -e "${YELLOW}[5/5] Generating results...${NC}"

# Find latest results file
LATEST_RESULT=$(ls -t "$SCRIPT_DIR/results"/*.json 2>/dev/null | head -1)

if [ -n "$LATEST_RESULT" ]; then
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}EVALUATION SUMMARY${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    python3 << 'EOF'
import json
import sys

try:
    result_file = sys.argv[1]
    with open(result_file) as f:
        data = json.load(f)

    print(f"Timestamp:   {data['timestamp']}")
    print(f"Dataset:     {data['dataset_size']} vulnerabilities")
    print(f"Analyses:    {data['analyses_count']} total")
    print()

    for tool, metrics in sorted(data['metrics'].items()):
        print(f"{tool}:")
        print(f"  Detection Rate:      {metrics['detection_rate']:>6.1f}%")
        print(f"  True Positive Rate:  {metrics['true_positive_rate']:>6.1f}%")
        print(f"  False Positive Rate: {metrics['false_positive_rate']:>6.1f}%")
        print(f"  Avg Patch Quality:   {metrics['avg_patch_quality']:>6.1f}/100")
        print(f"  Avg Analysis Time:   {metrics['avg_detection_time']:>6.2f}s")
        print(f"  Successful Patches:  {metrics['successful_patches']:>6}/{metrics['total_analyses']}")
        print(f"  Cost Estimate:       ${metrics['cost_estimate']:>8.2f}")
        print()

except Exception as e:
    print(f"Error reading results: {e}")
    sys.exit(1)
EOF
python3 - "$LATEST_RESULT"

    echo -e "${GREEN}✓ Full results: $LATEST_RESULT${NC}"
else
    echo -e "${YELLOW}⚠ No results file generated${NC}"
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Benchmark Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Next steps:"
echo "  1. Review results in: $SCRIPT_DIR/results/"
echo "  2. Run full 600-vulnerability benchmark: DATASET_LIMIT=600 DATASET_SOURCE=huggingface ./benchmark/run_benchmark.sh"
echo "  3. Use Docker: docker-compose -f benchmark/docker-compose.yml up"
echo ""
