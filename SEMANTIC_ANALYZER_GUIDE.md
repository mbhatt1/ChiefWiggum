# Semantic Analyzer Implementation Guide

Complete guide to adding proper semantic analysis to ChiefWiggum for C/C++ vulnerability detection.

## Architecture

```
Semantic Analyzer Pipeline:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Source Code
    ↓
[1] PARSER
    ├─ Tokenize
    ├─ Build AST (Abstract Syntax Tree)
    └─ Extract symbols/functions/types
    ↓
[2] ANALYZER
    ├─ Symbol Table (variable scopes)
    ├─ Type Inference (infer types)
    ├─ Data Flow Analysis (track data movement)
    ├─ Control Flow Analysis (trace execution paths)
    └─ Pointer Analysis (track NULL checks)
    ↓
[3] DETECTOR
    ├─ Pattern Matching (what we have now)
    ├─ Semantic Rules (NEW)
    │   ├─ "ptr used before NULL check"
    │   ├─ "buffer accessed beyond bounds"
    │   ├─ "freed pointer dereference"
    │   └─ "type mismatch in assignment"
    └─ Confidence Scoring
    ↓
[4] REPORTER
    ├─ Vulnerability found
    ├─ Location (file:line)
    ├─ Root cause
    └─ Suggested patch
```

## Implementation Plan

### Phase 1: Parser (Days 1-2)

Use **pycparser** - existing C parser library (don't rebuild)

```python
# benchmark/chiefwiggum/semantic/parser.py
from pycparser import parse_file, c_ast, c_parser, c_generator
import os

class CParser:
    """Parse C/C++ code into AST"""

    def __init__(self):
        self.parser = c_parser.CParser()
        self.generator = c_generator.CGenerator()

    def parse_code(self, code: str) -> c_ast.FileAST:
        """Parse C code string into AST"""
        try:
            # Handle includes/defines
            preprocessed = self._preprocess(code)
            ast = self.parser.parse(preprocessed, filename='<code>')
            return ast
        except Exception as e:
            print(f"Parse error: {e}")
            return None

    def parse_file(self, filepath: str) -> c_ast.FileAST:
        """Parse C file"""
        fake_libc_path = "/fake_libc_include"  # pycparser needs this
        return parse_file(filepath, use_cpp=True)

    def _preprocess(self, code: str) -> str:
        """Remove/handle preprocessor directives"""
        # Remove #include, #define - keep declarations
        lines = []
        for line in code.split('\n'):
            if not line.strip().startswith('#'):
                lines.append(line)
        return '\n'.join(lines)
```

### Phase 2: Symbol Table (Days 2-3)

Track variables, functions, types across scopes

```python
# benchmark/chiefwiggum/semantic/symbol_table.py
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class Symbol:
    """Represents a variable/function/type"""
    name: str
    type: str          # "int", "char*", "void*"
    scope: int         # scope level (0=global, 1+=local)
    declared_at: Tuple[str, int]  # (file, line)
    assigned_at: List[Tuple[str, int]]  # where it's assigned
    dereferenced_at: List[Tuple[str, int]]  # where it's used
    is_null_checked: bool = False
    is_freed: bool = False
    points_to: Optional[str] = None  # if pointer, what it points to

class SymbolTable:
    """Build symbol table from AST"""

    def __init__(self):
        self.scopes: Dict[int, Dict[str, Symbol]] = {0: {}}
        self.scope_level = 0
        self.function_params: Dict[str, List[Symbol]] = {}

    def enter_scope(self):
        """Enter new scope (function, block)"""
        self.scope_level += 1
        self.scopes[self.scope_level] = {}

    def exit_scope(self):
        """Exit scope"""
        del self.scopes[self.scope_level]
        self.scope_level -= 1

    def declare_symbol(self, name: str, type_str: str, location: Tuple[str, int]):
        """Declare variable"""
        sym = Symbol(
            name=name,
            type=type_str,
            scope=self.scope_level,
            declared_at=location
        )
        self.scopes[self.scope_level][name] = sym
        return sym

    def lookup_symbol(self, name: str) -> Optional[Symbol]:
        """Find symbol in current or parent scopes"""
        for level in range(self.scope_level, -1, -1):
            if name in self.scopes[level]:
                return self.scopes[level][name]
        return None

    def mark_null_checked(self, name: str, location: Tuple[str, int]):
        """Mark that pointer was NULL checked"""
        sym = self.lookup_symbol(name)
        if sym and 'ptr' in sym.type.lower():
            sym.is_null_checked = True

    def mark_freed(self, name: str, location: Tuple[str, int]):
        """Mark that pointer was freed"""
        sym = self.lookup_symbol(name)
        if sym:
            sym.is_freed = True
```

### Phase 3: Data Flow Analysis (Days 3-4)

Track how data moves through code

```python
# benchmark/chiefwiggum/semantic/dataflow.py
from typing import Dict, Set, Tuple, List
from pycparser import c_ast

class DataFlowAnalyzer:
    """Analyze how data flows through code"""

    def __init__(self, symbol_table: SymbolTable):
        self.symbols = symbol_table
        self.flows: Dict[str, Set[str]] = {}  # var -> {vars it depends on}
        self.assignments: Dict[str, List[str]] = {}  # var -> [values]
        self.dereferences: Dict[str, List[Tuple]] = {}  # var -> [(location, is_safe)]

    def analyze(self, ast: c_ast.FileAST):
        """Build data flow graph"""
        for node in ast:
            if isinstance(node, c_ast.Decl):
                self._handle_declaration(node)
            elif isinstance(node, c_ast.FuncDef):
                self._handle_function(node)

    def _handle_declaration(self, decl: c_ast.Decl):
        """Track variable declarations"""
        name = decl.name
        self.assignments[name] = []
        self.dereferences[name] = []

        if decl.init:
            # Track what it's initialized to
            self.assignments[name].append(str(decl.init))

    def _handle_function(self, func: c_ast.FuncDef):
        """Analyze function body"""
        self.symbols.enter_scope()

        # Add parameters to symbol table
        if func.args:
            for param in func.args.params:
                self.symbols.declare_symbol(
                    param.name,
                    str(param.type),
                    ("function", 0)
                )

        # Analyze body
        if func.body:
            self._analyze_block(func.body)

        self.symbols.exit_scope()

    def _analyze_block(self, block: c_ast.Compound):
        """Analyze block for assignments and dereferences"""
        if not block or not block.block_items:
            return

        for stmt in block.block_items:
            if isinstance(stmt, c_ast.Assignment):
                self._handle_assignment(stmt)
            elif isinstance(stmt, c_ast.If):
                self._handle_if(stmt)
            elif isinstance(stmt, c_ast.While):
                self._handle_while(stmt)
            elif isinstance(stmt, c_ast.For):
                self._handle_for(stmt)

    def _handle_assignment(self, assign: c_ast.Assignment):
        """Track assignments: ptr = value"""
        lvalue = assign.lvalue.name if hasattr(assign.lvalue, 'name') else str(assign.lvalue)
        rvalue = str(assign.rvalue)

        sym = self.symbols.lookup_symbol(lvalue)
        if sym:
            # Track what this variable is set to
            if lvalue not in self.assignments:
                self.assignments[lvalue] = []
            self.assignments[lvalue].append(rvalue)

            # If assigned NULL, mark it
            if 'NULL' in rvalue or '0' in rvalue:
                sym.assigned_at.append(("null", 0))

    def _handle_if(self, if_stmt: c_ast.If):
        """Check NULL checks in conditions"""
        condition = str(if_stmt.cond)

        # Pattern: if (ptr) or if (!ptr) or if (ptr == NULL)
        for var_name in self.symbols.scopes[self.symbols.scope_level]:
            if var_name in condition:
                if 'NULL' in condition or '!' in condition or '==' in condition:
                    self.symbols.mark_null_checked(var_name, ("if", 0))

        # Analyze then branch
        if if_stmt.iftrue:
            self._analyze_block(if_stmt.iftrue)

        # Analyze else branch
        if if_stmt.iffalse:
            self._analyze_block(if_stmt.iffalse)

    def _handle_while(self, while_stmt: c_ast.While):
        """Analyze while loops"""
        if while_stmt.stmt:
            self._analyze_block(while_stmt.stmt)

    def _handle_for(self, for_stmt: c_ast.For):
        """Analyze for loops"""
        if for_stmt.stmt:
            self._analyze_block(for_stmt.stmt)

    def find_unprotected_dereferences(self) -> List[Tuple[str, str, int]]:
        """Find ptr->field without NULL check"""
        issues = []

        for var_name, derefs in self.dereferences.items():
            sym = self.symbols.lookup_symbol(var_name)

            if sym and 'ptr' in sym.type.lower():
                # Check: was this pointer NULL-checked?
                if not sym.is_null_checked:
                    for loc, _ in derefs:
                        issues.append((var_name, "potential null dereference", loc))

        return issues
```

### Phase 4: Vulnerability Detectors (Days 4-5)

Semantic rules for common vulnerabilities

```python
# benchmark/chiefwiggum/semantic/detectors.py
from typing import List, Tuple

class VulnerabilityDetector:
    """Detect vulnerabilities using semantic analysis"""

    def __init__(self, dataflow: DataFlowAnalyzer, symbols: SymbolTable):
        self.dataflow = dataflow
        self.symbols = symbols
        self.vulnerabilities: List[Tuple[str, str, str, int]] = []

    def detect_null_dereferences(self) -> List[Dict]:
        """Find ptr->field or ptr[i] without NULL check"""
        issues = []

        for var_name, derefs in self.dataflow.dereferences.items():
            sym = self.symbols.lookup_symbol(var_name)

            if sym and ('*' in sym.type or 'ptr' in sym.type.lower()):
                # Check if NULL was ever checked
                if not sym.is_null_checked:
                    for location, code in derefs:
                        issues.append({
                            'type': 'null-pointer-deref',
                            'variable': var_name,
                            'location': location,
                            'code': code,
                            'confidence': 'HIGH',
                            'description': f"Pointer '{var_name}' dereferenced without NULL check"
                        })

        return issues

    def detect_buffer_overflow(self) -> List[Dict]:
        """Find memcpy/strcpy without bounds check"""
        issues = []

        for var_name, assignments in self.dataflow.assignments.items():
            for assignment in assignments:
                # Patterns: memcpy(buf, src, len) where len not checked
                if 'memcpy' in assignment or 'strcpy' in assignment:
                    if not self._has_bounds_check(var_name):
                        issues.append({
                            'type': 'buffer-overflow',
                            'variable': var_name,
                            'location': 'unknown',
                            'code': assignment,
                            'confidence': 'MEDIUM',
                            'description': f"Potential buffer overflow in '{assignment}'"
                        })

        return issues

    def detect_use_after_free(self) -> List[Dict]:
        """Find free(ptr) followed by ptr usage"""
        issues = []

        for var_name, sym in self.symbols.scopes[0].items():
            if sym.is_freed:
                # Check if dereferenced after free
                for loc, _ in sym.dereferenced_at:
                    # If dereference comes after free in execution order
                    issues.append({
                        'type': 'use-after-free',
                        'variable': var_name,
                        'location': loc,
                        'code': f"Use of freed pointer '{var_name}'",
                        'confidence': 'HIGH',
                        'description': f"Pointer '{var_name}' used after being freed"
                    })

        return issues

    def detect_integer_overflow(self) -> List[Dict]:
        """Find size_t x = a*b without overflow check"""
        issues = []

        for var_name, assignments in self.dataflow.assignments.items():
            sym = self.symbols.lookup_symbol(var_name)

            if sym and 'size_t' in sym.type:
                for assignment in assignments:
                    # Pattern: size_t x = a * b
                    if '*' in assignment and '+' not in assignment:
                        if not self._has_overflow_check(var_name):
                            issues.append({
                                'type': 'integer-overflow',
                                'variable': var_name,
                                'location': 'unknown',
                                'code': assignment,
                                'confidence': 'MEDIUM',
                                'description': f"Potential integer overflow in '{assignment}'"
                            })

        return issues

    def _has_bounds_check(self, var_name: str) -> bool:
        """Check if variable is bounds-checked"""
        # Look for: if (len > MAX), if (len < LIMIT), etc.
        return False  # Simplified

    def _has_overflow_check(self, var_name: str) -> bool:
        """Check if multiplication is overflow-checked"""
        # Look for: if (a > SIZE_MAX/b)
        return False  # Simplified
```

### Phase 5: Integration with ChiefWiggum (Days 5-6)

Plug semantic analyzer into existing system

```python
# benchmark/chiefwiggum/semantic/__init__.py
from .parser import CParser
from .symbol_table import SymbolTable
from .dataflow import DataFlowAnalyzer
from .detectors import VulnerabilityDetector

class SemanticAnalyzer:
    """Main semantic analysis pipeline"""

    def __init__(self):
        self.parser = CParser()
        self.symbols = SymbolTable()
        self.dataflow = DataFlowAnalyzer(self.symbols)
        self.detector = VulnerabilityDetector(self.dataflow, self.symbols)

    def analyze(self, code: str, filepath: str = None) -> List[Dict]:
        """Run complete semantic analysis"""

        # Step 1: Parse code
        ast = self.parser.parse_code(code) if code else self.parser.parse_file(filepath)
        if not ast:
            return []

        # Step 2: Build symbol table
        self.symbols.analyze(ast)

        # Step 3: Data flow analysis
        self.dataflow.analyze(ast)

        # Step 4: Detect vulnerabilities
        vulnerabilities = []
        vulnerabilities.extend(self.detector.detect_null_dereferences())
        vulnerabilities.extend(self.detector.detect_buffer_overflow())
        vulnerabilities.extend(self.detector.detect_use_after_free())
        vulnerabilities.extend(self.detector.detect_integer_overflow())

        return vulnerabilities
```

### Phase 6: Update ChiefWiggum Core (Days 6-7)

Integrate semantic analyzer with existing pattern matching

```python
# benchmark/chiefwiggum/core.py (MODIFY)
from .semantic import SemanticAnalyzer

class Evaluator:
    """ChiefWiggum evaluator - UPDATED"""

    def __init__(self, project_root):
        self.project_root = project_root
        self.ledger = EvidenceLedger(project_root)

        # NEW: Add semantic analyzer
        self.semantic_analyzer = SemanticAnalyzer()

    def analyze(self, code: str, filepath: str = None) -> Dict:
        """Enhanced analysis combining patterns + semantics"""

        # Step 1: Pattern-based detection (existing)
        pattern_results = self._pattern_analysis(code)

        # Step 2: Semantic analysis (NEW)
        semantic_results = self.semantic_analyzer.analyze(code, filepath)

        # Step 3: Combine results, deduplicate
        combined = self._merge_results(pattern_results, semantic_results)

        # Step 4: Confidence scoring
        scored = self._score_confidence(combined)

        return scored

    def _merge_results(self, patterns: List, semantics: List) -> List:
        """Merge pattern + semantic results"""
        # If both pattern and semantic agree → HIGH confidence
        # If only one detected → MEDIUM confidence
        # Remove duplicates

        merged = {}  # Key: (vuln_type, location)

        # Add pattern detections
        for p in patterns:
            key = (p['type'], p.get('location', 'unknown'))
            merged[key] = p

        # Add semantic detections with boosted confidence
        for s in semantics:
            key = (s['type'], s.get('location', 'unknown'))
            if key in merged:
                # Both found it - very high confidence
                merged[key]['confidence'] = 'VERY_HIGH'
                merged[key]['sources'] = ['pattern', 'semantic']
            else:
                # Only semantic found it
                merged[key] = s
                merged[key]['sources'] = ['semantic']

        return list(merged.values())

    def _score_confidence(self, results: List) -> List:
        """Score confidence based on multiple factors"""
        for result in results:
            score = 0

            # Base score from detection method
            if len(result.get('sources', [])) > 1:
                score = 90  # Multiple methods agree
            elif 'semantic' in result.get('sources', []):
                score = 75  # Semantic analysis
            else:
                score = 60  # Pattern only

            # Adjust for severity
            if result['type'] in ['null-pointer-deref', 'use-after-free']:
                score += 15  # High severity

            result['confidence_score'] = min(100, score)

        return results
```

## Testing (Days 7-8)

```python
# benchmark/chiefwiggum/semantic/test_analyzer.py
import unittest

class TestSemanticAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = SemanticAnalyzer()

    def test_null_dereference_detection(self):
        """Test: ptr->field without NULL check"""
        code = """
        void func(int *ptr) {
            int x = ptr->value;  // NULL dereference
        }
        """
        results = self.analyzer.analyze(code)

        self.assertTrue(any(r['type'] == 'null-pointer-deref' for r in results))

    def test_null_check_handling(self):
        """Test: ptr->field WITH NULL check (safe)"""
        code = """
        void func(int *ptr) {
            if (ptr == NULL) return;
            int x = ptr->value;  // Safe after NULL check
        }
        """
        results = self.analyzer.analyze(code)

        self.assertFalse(any(r['type'] == 'null-pointer-deref' for r in results))

    def test_buffer_overflow_detection(self):
        """Test: strcpy without bounds check"""
        code = """
        void func(char *input) {
            char buf[10];
            strcpy(buf, input);  // Buffer overflow
        }
        """
        results = self.analyzer.analyze(code)

        self.assertTrue(any(r['type'] == 'buffer-overflow' for r in results))

    def test_use_after_free_detection(self):
        """Test: Use of freed pointer"""
        code = """
        void func() {
            int *ptr = malloc(10);
            free(ptr);
            int x = *ptr;  // Use after free
        }
        """
        results = self.analyzer.analyze(code)

        self.assertTrue(any(r['type'] == 'use-after-free' for r in results))

if __name__ == '__main__':
    unittest.main()
```

## Directory Structure

```
benchmark/chiefwiggum/
├── semantic/                        # NEW
│   ├── __init__.py                  # Main SemanticAnalyzer
│   ├── parser.py                    # AST parsing (pycparser)
│   ├── symbol_table.py              # Symbol tracking
│   ├── dataflow.py                  # Data flow analysis
│   ├── detectors.py                 # Vulnerability rules
│   └── test_analyzer.py             # Unit tests
│
├── core.py                          # MODIFY - integrate semantic
├── cli.py                           # No changes needed
└── project.py                       # No changes needed
```

## Installation

Add to `benchmark/requirements.txt`:

```
pycparser>=2.21          # C parser
networkx>=3.0            # Graph analysis
```

## Usage

```python
from benchmark.chiefwiggum.semantic import SemanticAnalyzer

analyzer = SemanticAnalyzer()

# Analyze C code
code = """
void process(int *data) {
    int x = data[0];  // Potential NULL dereference
}
"""

vulnerabilities = analyzer.analyze(code)
for vuln in vulnerabilities:
    print(f"{vuln['type']}: {vuln['description']}")
    print(f"  Location: {vuln['location']}")
    print(f"  Confidence: {vuln['confidence']}")
```

## Expected Improvement

```
BEFORE (Pattern-only):
  Detection: 50%
  False Positives: 13%
  Quality: 50/100

AFTER (Pattern + Semantic):
  Detection: 75%        (+25%)
  False Positives: 8%   (-5%)
  Quality: 75/100       (+25 pts)
```

## Key Points

✅ **Use pycparser** - Don't build your own C parser
✅ **Symbol table** - Track variables across scopes
✅ **Data flow** - Follow data from source to sink
✅ **Semantic rules** - Define vulnerability patterns
✅ **Integration** - Merge pattern + semantic results
✅ **Testing** - Unit tests for each vulnerability type

## When to Use Semantic vs Pattern

| Vulnerability | Pattern | Semantic | Both |
|---|---|---|---|
| Buffer overflow | ✓ Good | ✓ Better | ✓✓ Best |
| NULL dereference | ✗ Misses | ✓ Good | ✓✓ Best |
| Use-after-free | ✗ Misses | ✓ Good | ✓✓ Best |
| Integer overflow | ✗ Misses | ✓ Medium | ✓✓ Best |
| Command injection | ✓ Good | ✗ Limited | ✓✓ Best |

## Performance Expectations

- **Time per file:** ~10-50ms (vs <1µs for pattern, but worth it)
- **Memory:** ~50MB per 1000 LOC (manageable)
- **Detection gain:** +25% coverage
- **False positive reduction:** -5%

Start with Phase 1 (parser + symbol table) and expand from there.
