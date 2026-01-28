# ChiefWiggum Improvements - Based on SEC-Bench Benchmark Results

## Current Performance Gap

```
ChiefWiggum:  50% detection, 50/100 patch quality, $0, <1µs
Claude Opus:  75% detection, 79/100 patch quality, $500, 3-8s
Gap:          -25% coverage, -29 points quality
```

## What to Add

### 1. SEMANTIC ANALYSIS MODULE (Highest Priority)

**Problem:** ChiefWiggum only does regex pattern matching. Misses:
- Context-dependent vulnerabilities
- Data flow across multiple functions
- Semantic understanding (intent vs syntax)

**Solution:** Add AST (Abstract Syntax Tree) analysis

```python
# benchmark/chiefwiggum/semantic_analyzer.py (NEW)
class SemanticAnalyzer:
    """Understand code intent, not just patterns"""

    def analyze_dataflow(self, code: str) -> Dict[str, List[str]]:
        """Track how data flows through code"""
        # Parse AST
        # Trace variable assignments
        # Find sources → sinks
        # Return flow graph

    def analyze_nullability(self, code: str) -> List[str]:
        """Find potential null pointer dereferences"""
        # Check if pointers are checked before use
        # Track NULL assignments
        # Find unchecked dereferences

    def analyze_type_safety(self, code: str) -> List[str]:
        """Find type confusion vulnerabilities"""
        # Infer types from assignments
        # Find casts without validation
        # Detect type mismatches
```

**Why:** This would catch the null pointer dereferences ChiefWiggum currently misses (gpac.cve-2023-5586).

---

### 2. PATCH GENERATION ENGINE (High Priority)

**Problem:** ChiefWiggum detects issues (50/100 score) but patches are basic

**Solution:** Template-based + semantic patch generation

```python
# benchmark/chiefwiggum/patch_generator.py (NEW)
class PatchGenerator:
    """Generate production-ready patches"""

    PATCHES = {
        "buffer-overflow": [
            ("memcpy(a,b,len)", "if(len > MAX) return -1; memcpy(a,b,len);"),
            ("strcpy(a,b)", "strncpy(a,b,sizeof(a)-1);"),
        ],
        "null-deref": [
            ("ptr->field", "if(!ptr) return NULL; ptr->field"),
            ("arr[i]", "if(!arr || i >= len) return NULL; arr[i]"),
        ],
        "integer-overflow": [
            ("size_t x = a*b", "if(a > SIZE_MAX/b) return -1; size_t x = a*b;"),
        ]
    }

    def generate_patch(self, vuln_type: str, location: str, code: str) -> str:
        """Generate semantic patch"""
        # Find exact vulnerable code
        # Apply template
        # Add bounds checks
        # Add error handling
        # Return patch + test
```

**Why:** Improves patch quality from 50 → 70+/100.

---

### 3. FALSE POSITIVE FILTERING (Medium Priority)

**Problem:** Need better confidence scoring to reduce false alarms

**Solution:** Multi-factor confidence scoring

```python
# benchmark/chiefwiggum/confidence_scorer.py (NEW)
class ConfidenceScorer:
    """Score detection confidence (HIGH/MEDIUM/LOW)"""

    def score_detection(self, detection: Detection) -> float:
        """0-100 confidence score"""
        score = 0

        # Pattern match strength (0-30)
        score += len(detection.matched_patterns) * 10

        # Context (0-30)
        if detection.has_null_check:      score -= 15  # Safe
        if detection.has_bounds_check:    score -= 10  # Safe
        if detection.has_try_catch:       score -= 5   # Some protection

        # Severity (0-30)
        if detection.is_user_input:       score += 20  # High severity
        if detection.crosses_boundary:    score += 10  # Medium severity

        # False positive history (0-10)
        if detection.type in self.false_positives:
            score -= 20

        return max(0, min(100, score))

    def is_real_vulnerability(self, score: float) -> bool:
        """Filter out noise"""
        return score >= 60  # High confidence only
```

**Why:** Reduces false positives, improves true positive rate.

---

### 4. SUPPORT FOR MORE VULNERABILITY CLASSES (Medium Priority)

**Current:** Limited to Java deserialization, STOMP, LDAP
**Need:** Expand to C/C++ memory safety

```python
# benchmark/chiefwiggum/detectors/ (EXPAND)
detectors = {
    # Existing (Java/JVM)
    "java-deserialization": JavaDeserializationDetector(),
    "ldap-injection": LdapInjectionDetector(),

    # NEW: C/C++ Memory Safety
    "heap-buffer-overflow": HeapBufferOverflowDetector(),
    "stack-buffer-overflow": StackBufferOverflowDetector(),
    "use-after-free": UseAfterFreeDetector(),
    "null-pointer-deref": NullPointerDerefDetector(),
    "integer-overflow": IntegerOverflowDetector(),

    # NEW: Other languages
    "python-pickle": PythonPickleDetector(),
    "javascript-eval": JavaScriptEvalDetector(),
}
```

**Why:** SEC-Bench has 600 C/C++ vulns; ChiefWiggum only handles Java patterns.

---

### 5. INTEGRATION WITH EXTERNAL TOOLS (Medium Priority)

**Leverage existing tools instead of rebuilding:**

```python
# benchmark/chiefwiggum/external_tools.py (NEW)
class ExternalToolIntegration:
    """Use CodeQL, Semgrep, etc. for better detection"""

    def run_codeql(self, code_path: str) -> List[Vulnerability]:
        """Query CodeQL database"""
        # Run: codeql query run --database=db queries/cpp/
        # Parse results
        # Return findings

    def run_semgrep(self, code_path: str) -> List[Vulnerability]:
        """Run Semgrep rules"""
        # Run: semgrep --config=p/security-audit code_path
        # Parse YAML output
        # Return findings

    def combine_results(self, results: List[List[Vuln]]) -> List[Vuln]:
        """Combine multiple tools, deduplicate, score confidence"""
        # Remove duplicates
        # Boost confidence if multiple tools agree
        # Return consolidated findings
```

**Why:** CodeQL + Semgrep already have 90%+ accuracy; ChiefWiggum can orchestrate them.

---

### 6. REGRESSION TEST GENERATION (Medium Priority)

**Problem:** Patches without tests aren't production-ready

```python
# benchmark/chiefwiggum/test_generator.py (NEW)
class RegressionTestGenerator:
    """Generate tests to prevent re-introduction of vulnerability"""

    def generate_test(self, vuln: Vulnerability) -> str:
        """Create test case"""
        test_template = {
            "buffer-overflow": """
                void test_buffer_overflow_blocked() {{
                    char buf[10];
                    // Should fail/error, not overflow
                    assert(memcpy_safe(buf, malicious_input, 100) == -1);
                }}
            """,
            "null-deref": """
                void test_null_deref_blocked() {{
                    MyObj *ptr = NULL;
                    // Should handle NULL gracefully
                    assert(access_field(ptr) != SEGFAULT);
                }}
            """
        }

        return test_template.get(vuln.type, "").format(
            vulnerable_call=vuln.code,
            fix=vuln.patch
        )
```

**Why:** Increases patch quality score (50 → 80+/100).

---

### 7. SANDBOX VALIDATION (Lower Priority)

**Actually test patches before recommending**

```python
# benchmark/chiefwiggum/sandbox.py (NEW)
class SandboxValidator:
    """Validate patch in isolated environment"""

    def validate_patch(self, original: str, patch: str) -> ValidationResult:
        """Build & test in Docker"""
        # 1. Build original code with sanitizers (ASAN/UBSAN)
        #    → Should detect vulnerability

        # 2. Build patched code with sanitizers
        #    → Should NOT detect vulnerability

        # 3. Run regression test
        #    → Should pass

        # 4. Check for new crashes
        #    → Should be zero

        return ValidationResult(
            patch_works=True,
            no_new_issues=True,
            improved_security=True
        )
```

**Why:** Ensures patches actually work before release.

---

## Implementation Roadmap

### Phase 1: Quick Wins (1 week, +15% detection)

```
✓ Add confidence scoring (filter false positives)
✓ Add C/C++ buffer overflow detector
✓ Add null pointer dereference detector
└─ Expected result: 60-65% detection
```

### Phase 2: Core Improvements (2 weeks, +10% detection)

```
✓ Add semantic analyzer (AST-based)
✓ Add dataflow analysis
✓ Add type inference
└─ Expected result: 70-75% detection
```

### Phase 3: Production Ready (2 weeks)

```
✓ Add patch generation engine
✓ Add regression test generation
✓ Add sandbox validation
└─ Expected result: 75-80% detection + 75+/100 patch quality
```

### Phase 4: Advanced (Optional, 1 month)

```
✓ Integrate CodeQL/Semgrep
✓ Add ML-based confidence scoring
✓ Multi-language support
└─ Expected result: 85%+ detection
```

---

## Code Structure

```
benchmark/chiefwiggum/
├── __init__.py
├── cli.py                    # (existing)
├── core.py                   # (existing)
├── project.py                # (existing)
│
├── semantic/                 # (NEW)
│   ├── __init__.py
│   ├── ast_analyzer.py       # AST parsing
│   ├── dataflow.py           # Data flow tracking
│   └── type_inference.py     # Type analysis
│
├── detectors/                # (EXPAND)
│   ├── __init__.py
│   ├── base.py               # Base detector class
│   ├── java/                 # (existing)
│   ├── c_cpp/                # (NEW)
│   │   ├── buffer_overflow.py
│   │   ├── null_deref.py
│   │   ├── use_after_free.py
│   │   └── integer_overflow.py
│   └── python/               # (NEW)
│
├── patching/                 # (NEW)
│   ├── __init__.py
│   ├── generator.py          # Patch generation
│   ├── validator.py          # Sandbox validation
│   └── test_generator.py     # Test creation
│
├── scoring/                  # (NEW)
│   ├── __init__.py
│   └── confidence.py         # Confidence scoring
│
└── tools/                    # (NEW)
    ├── __init__.py
    ├── codeql.py
    └── semgrep.py
```

---

## Expected Improvements

### Detection Rate
```
Before: 50%
Quick Wins (Phase 1): 60-65%
With Semantics (Phase 2): 70-75%
Production Ready (Phase 3): 75-80%
Advanced (Phase 4): 85%+
```

### Patch Quality
```
Before: 50/100
Phase 1: 55/100 (better filtering)
Phase 2: 65/100 (semantic understanding)
Phase 3: 75/100 (test coverage)
Phase 4: 80+/100 (validated)
```

### Cost
```
Current: $0 (free)
New: Still $0 (no API calls)
vs Claude: $250-500 per 100 vulns
```

### Speed
```
Current: <1µs per vulnerability
New: 1-50ms per vulnerability (still faster than Claude's 2-5s)
```

---

## Priority Ranking

1. **HIGH** - Add semantic analyzer + null deref detector
   - Closes 50% of coverage gap
   - Still free
   - Same speed

2. **HIGH** - Add confidence scorer + false positive filter
   - Improves accuracy
   - Easier to implement
   - Quick win

3. **HIGH** - Add patch generation
   - Increases quality from 50 → 70/100
   - Template-based approach is simple

4. **MEDIUM** - Add C/C++ memory safety detectors
   - SEC-Bench is 100% C/C++
   - Can reuse patterns from Semgrep

5. **MEDIUM** - Integrate external tools (CodeQL/Semgrep)
   - Leverage battle-tested tools
   - No need to reimplement detectors

6. **LOW** - Add sandbox validation
   - Nice to have
   - Can be external CI step

7. **LOW** - Add ML-based scoring
   - Future optimization
   - Only if pattern-based plateaus

---

## Success Criteria

✓ **Detection:** Match Claude Opus (75%+)
✓ **Quality:** Exceed Claude Opus (80+/100)
✓ **Cost:** Stay free ($0)
✓ **Speed:** Faster than Claude (<50ms vs 3-8s)
✓ **Coverage:** Support C/C++, Java, Python

**Result:** ChiefWiggum becomes faster, cheaper, and better than Claude for vulnerability detection.
