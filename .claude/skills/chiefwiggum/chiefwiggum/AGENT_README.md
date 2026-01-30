# Universal Vulnerability Discovery Agent

ChiefWiggum now includes a **Universal Vulnerability Discovery Agent** that performs semantic code analysis to find exploitable vulnerabilities across any language and framework.

## What It Does

The agent:
- **Analyzes semantically** (understands code meaning, not just pattern matching)
- **Asks universal questions** that work on any codebase
- **Discovers patterns** and extracts learnings
- **Finds similar code** matching vulnerability patterns
- **Identifies exploit chains** (how vulns combine for greater impact)
- **Generates patches** and regression tests
- **Prioritizes by threat** model context
- **Loops iteratively** until all vulnerabilities discovered

## Commands

### `/chiefwiggum hunt` - Core Vulnerability Discovery

Hunt for ALL exploitable vulnerabilities in a codebase using semantic analysis.

```bash
/chiefwiggum hunt --path /path/to/activemq --threat-model threat.json
```

**What it does:**
1. Loads the entire codebase
2. Asks semantic questions (entry points, validation gaps, dangerous sinks, etc.)
3. Analyzes findings and rates exploitability
4. Extracts vulnerability patterns
5. Searches for similar code matching patterns
6. Identifies attack chains
7. Generates patches for each vulnerability
8. Prioritizes by threat model

**Output:**
- List of vulnerabilities (sorted by threat score)
- Exploit chains showing how vulns combine
- Suggested patches and tests
- Control mappings (C-001 to C-012)

**Example output:**
```
UNIVERSAL VULNERABILITY DISCOVERY AGENT
========================================

Target: ./activemq-spring
Threat Model: Default
Max Iterations: 5

Starting semantic vulnerability discovery...
✓ Hunt complete (5 iterations)
  Found 47 exploitable vulnerabilities

1. JMX Discovery RCE
   Location: XBeanBrokerFactory.java:60
   Severity: 9.8/10
   Exploitability: 95%
   Threat Score: 9.3
   Pattern: validation_gap

2. Parameter Injection in BrokerService
   ...

=== EXPLOIT CHAINS ===

• Auth Bypass + Parameter Injection = Critical RCE
  Unauthenticated attacker calls unprotected RPC method with malicious parameter
  Impact: Remote Code Execution
```

### `/chiefwiggum similar` - Find Similar Patterns

Find all code matching a vulnerability pattern (even if written differently).

```bash
/chiefwiggum similar --path ./code --pattern "Remote Resource Loading" --limit 10
```

Finds all code that matches the semantic pattern, regardless of language or exact implementation.

### `/chiefwiggum chains` - Show Exploit Chains

Find how a specific vulnerability chains with others for amplified impact.

```bash
/chiefwiggum chains --path ./code auto_0
```

Shows:
- How multiple vulnerabilities combine
- Attack sequence
- Difficulty level
- Real-world impact

### `/chiefwiggum patch` - Generate Patches

Generate patch code, regression tests, and control mappings.

```bash
/chiefwiggum patch auto_0 --path .
```

Returns:
- Patch code (ready to review)
- Regression test (prevents re-exposure)
- Control ID (C-002, C-007, etc.)

### `/chiefwiggum analyze` - Quick Scan

Fast vulnerability scan without iterative looping (1 iteration only).

```bash
/chiefwiggum analyze --path ./code --language java
```

Good for quick checks on code changes.

### `/chiefwiggum report` - Comprehensive Report

Generate executive-level vulnerability report.

```bash
/chiefwiggum report --path . --threat-model threat.json
```

Includes:
- Executive summary
- Prioritized vulnerability list
- Exploit chains
- Remediation timeline
- Control mapping
- Effort estimates

## Threat Models

Pass a JSON threat model to prioritize vulnerabilities by your actual threat:

```json
{
  "unauthenticated_attacker": true,
  "network_exposed": true,
  "sensitive_data": true,
  "business_critical": true,
  "compliance_requirements": ["PCI-DSS", "SOC-2"]
}
```

The agent will boost threat scores for vulnerabilities matching your threat model.

## How It Works

### Iteration Loop

The agent iteratively refines vulnerability discovery:

```
Iteration 1: Ask "Where is user input?" → Find entry points
Iteration 2: Ask "Is it validated?" → Find validation gaps
Iteration 3: Ask "What sinks exist?" → Find dangerous functions
Iteration 4: Ask "Can input reach sink?" → Confirm exploitability
Iteration 5: Ask "Are similar patterns elsewhere?" → Find duplicates
```

### Pattern Extraction

For each found vulnerability, the agent extracts the semantic pattern:

```
Specific: JMX Discovery → Parameter Injection → Remote Resource → RCE
Pattern:  Entry Point → Unvalidated Parameter → External Resource → Dangerous Sink
Universal: User Input → No Validation → Reaches Sink → Execution
```

Then searches for all code matching the universal pattern.

### Exploit Chain Detection

Identifies how vulnerabilities combine:

```
Found:
- Parameter injection (medium severity)
- No auth on RPC (low severity individually)
- ProcessBuilder available (low individually)

Chains them:
RPC Parameter Injection + No Auth + Gadget = CRITICAL RCE
```

## Integration with Evidence Ledger

After discovery, feed findings into ChiefWiggum's evidence system:

```bash
# Hunt finds vulnerabilities
/chiefwiggum hunt --path ./code > findings.json

# Record them in evidence ledger
for vuln in findings; do
  /chiefwiggum record $vuln_id \
    --confirmed \
    --location "$location" \
    --action PATCH \
    --patch-location "$patch_location" \
    --test-case "$test_case"
done

# Generate hardening backlog
/chiefwiggum report generate
```

## Advanced Usage

### Custom Threat Model

Create threat.json:
```json
{
  "attacker_type": "external_network",
  "has_auth": false,
  "critical_assets": ["message_broker", "admin_console"],
  "compliance": ["SOC-2"]
}
```

Then hunt with threat awareness:
```bash
/chiefwiggum hunt --path ./code --threat-model threat.json
```

### Focus on Specific Pattern

Hunt for only deserialization gadgets:
```bash
/chiefwiggum similar --path ./code --pattern "gadget_chain" --limit 20
```

### Generate Hardening Roadmap

```bash
# Hunt
/chiefwiggum hunt --path ./code

# Get patch recommendations
/chiefwiggum patch auto_0
/chiefwiggum patch auto_1
...

# Create PR with all patches
git checkout -b hardening/chiefwiggum-patches
# Apply patches
git commit -am "ChiefWiggum: Security hardening patches"
git push origin hardening/chiefwiggum-patches
# Open PR
```

## Comparison with Old Approach

### Before (Pattern Matching)
- Look for `ObjectInputStream` in code
- See if it deserializes untrusted data
- Limited to specific patterns
- Miss similar vulnerabilities
- No chain detection

### After (Semantic Analysis)
- Ask: "Where is user input?"
- Ask: "Is it validated?"
- Ask: "What dangerous sinks exist?"
- Ask: "Can input reach sinks?"
- Find ALL instances, even written differently
- Discover attack chains automatically
- Iterate until complete

## Performance Notes

- **Quick mode** (`analyze`): ~2-5 minutes for medium codebase
- **Full hunt** (5 iterations): ~15-30 minutes for medium codebase
- **Language agnostic**: Same speed regardless of language mix

## Success Metrics

You'll know it's working when:
- ✅ Finds vulnerabilities you knew about
- ✅ Finds similar vulnerabilities automatically
- ✅ Identifies attack chains
- ✅ Generates patches
- ✅ Reduces false positives (exploitability checking)
- ✅ Works on new/unfamiliar code
- ✅ Works across languages

## Example: Full Workflow

```bash
# 1. Hunt for vulnerabilities
/chiefwiggum hunt \
  --path ./activemq-spring \
  --threat-model threat.json \
  --max-iterations 5

# 2. View exploit chains
/chiefwiggum chains --path ./activemq-spring auto_0

# 3. Get patches
/chiefwiggum patch auto_0
/chiefwiggum patch auto_1

# 4. Generate comprehensive report
/chiefwiggum report --path . --threat-model threat.json

# 5. Integrate with ChiefWiggum evidence
/chiefwiggum record auto_0 \
  --confirmed \
  --location "XBeanBrokerFactory.java:60" \
  --description "JMX Discovery RCE" \
  --action PATCH \
  --patch-location "XBeanBrokerFactory.java:60-61"

# 6. Create hardening backlog
/chiefwiggum report generate
```

## Next Steps

1. Run `hunt` on your target codebase
2. Review vulnerabilities and threat scores
3. Examine exploit chains
4. Generate patches for critical issues
5. Create hardening roadmap with timeline
6. Deploy patches and verify with regression tests
