"""
Semantic Analyzer for ChiefWiggum
Performs data flow analysis, type analysis, and semantic vulnerability detection
"""

from typing import List, Dict, Optional, Tuple
from .parser import CParser
from .symbol_table import SymbolTable, Symbol
import re


class SemanticAnalyzer:
    """
    Main semantic analysis engine

    Pipeline:
    1. Parse code to AST
    2. Build symbol table
    3. Analyze data flows
    4. Detect semantic vulnerabilities
    """

    def __init__(self):
        """Initialize analyzer"""
        self.parser = CParser()
        self.symbol_table = SymbolTable()

    def analyze(self, code: str, filepath: str = "unknown") -> List[Dict]:
        """
        Run complete semantic analysis

        Args:
            code: C source code
            filepath: Source file path (for debugging)

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Step 1: Parse code
        ast = self.parser.parse_code(code)
        if not ast:
            # Fallback: use simple text analysis
            return self._simple_analysis(code, filepath)

        # Step 2: Build symbol table
        self._build_symbol_table(code, filepath)

        # Step 3: Detect vulnerabilities
        vulnerabilities.extend(self._detect_null_dereferences(code, filepath))
        vulnerabilities.extend(self._detect_buffer_overflow(code, filepath))
        vulnerabilities.extend(self._detect_use_after_free(code, filepath))
        vulnerabilities.extend(self._detect_uninitialized_use(code, filepath))

        return vulnerabilities

    def _build_symbol_table(self, code: str, filepath: str):
        """
        Build symbol table from code text

        Simple regex-based approach when AST parsing unavailable
        """
        self.symbol_table = SymbolTable()

        # Match declarations: type name;
        decl_pattern = r'(?:int|char|void|float|size_t|unsigned|signed|long|short)\s*\*?\s*(\w+)'

        for match in re.finditer(decl_pattern, code):
            var_name = match.group(1)
            line_no = code[:match.start()].count('\n') + 1

            # Determine type
            line = code[max(0, match.start()-50):match.start()+50]
            is_pointer = '*' in line
            is_array = '[' in line

            type_str = ""
            if is_pointer:
                type_str += "*"
            if is_array:
                type_str += "[]"

            self.symbol_table.declare_symbol(
                var_name,
                type_str or "unknown",
                (filepath, line_no)
            )

    def _detect_null_dereferences(self, code: str, filepath: str) -> List[Dict]:
        """
        Detect potential NULL pointer dereferences

        Pattern:
        - Pointer dereference (->  or *)
        - Without prior NULL check
        """
        issues = []
        lines = code.split('\n')

        for i, line in enumerate(lines):
            # Pattern: ptr->field or *ptr
            if '->' in line or ('^' not in line and ' *' in line):
                # Extract variable name
                match = re.search(r'(\w+)\s*->', line)
                if match:
                    var_name = match.group(1)
                    sym = self.symbol_table.lookup_symbol(var_name)

                    if sym and sym.is_pointer():
                        # Check if NULL was checked in previous lines
                        has_null_check = False
                        for j in range(max(0, i-5), i):
                            if var_name in lines[j] and ('NULL' in lines[j] or 'if (' in lines[j]):
                                has_null_check = True
                                break

                        if not has_null_check:
                            issues.append({
                                'type': 'null-pointer-deref',
                                'variable': var_name,
                                'location': f"{filepath}:{i+1}",
                                'code': line.strip(),
                                'confidence': 'MEDIUM',
                                'description': f"Pointer '{var_name}' may be dereferenced without NULL check"
                            })

        return issues

    def _detect_buffer_overflow(self, code: str, filepath: str) -> List[Dict]:
        """
        Detect potential buffer overflows

        Pattern:
        - memcpy/strcpy/strcat without bounds check
        - Fixed-size buffer with unbounded input
        """
        issues = []
        lines = code.split('\n')

        dangerous_funcs = ['strcpy', 'strcat', 'sprintf', 'gets']

        for i, line in enumerate(lines):
            for func in dangerous_funcs:
                if func in line:
                    # Check for bounds check nearby
                    has_bounds_check = False
                    for j in range(max(0, i-3), min(len(lines), i+3)):
                        if 'if' in lines[j] and any(k in lines[j] for k in ['<', '>', '<=', '>=']):
                            has_bounds_check = True
                            break

                    if not has_bounds_check:
                        issues.append({
                            'type': 'buffer-overflow',
                            'function': func,
                            'location': f"{filepath}:{i+1}",
                            'code': line.strip(),
                            'confidence': 'HIGH',
                            'description': f"Dangerous function '{func}' without bounds checking"
                        })

        return issues

    def _detect_use_after_free(self, code: str, filepath: str) -> List[Dict]:
        """
        Detect use-after-free vulnerabilities

        Pattern:
        - free(ptr)
        - Followed by ptr dereference
        """
        issues = []
        lines = code.split('\n')

        for i, line in enumerate(lines):
            if 'free(' in line:
                # Extract freed variable
                match = re.search(r'free\(\s*(\w+)', line)
                if match:
                    freed_var = match.group(1)

                    # Check for use after free (next 5 lines)
                    for j in range(i+1, min(len(lines), i+6)):
                        if freed_var in lines[j] and '->' in lines[j]:
                            issues.append({
                                'type': 'use-after-free',
                                'variable': freed_var,
                                'location': f"{filepath}:{j+1}",
                                'code': lines[j].strip(),
                                'confidence': 'HIGH',
                                'description': f"Variable '{freed_var}' used after being freed at line {i+1}"
                            })

        return issues

    def _detect_uninitialized_use(self, code: str, filepath: str) -> List[Dict]:
        """
        Detect use of uninitialized variables

        Pattern:
        - Variable declared but not assigned
        - Then used
        """
        issues = []

        for sym in self.symbol_table.get_uninitialized_symbols():
            if sym.dereferenced_at:
                # Used without initialization
                issues.append({
                    'type': 'uninitialized-use',
                    'variable': sym.name,
                    'location': f"{filepath}:{sym.dereferenced_at[0][1]}",
                    'code': f"Use of uninitialized variable '{sym.name}'",
                    'confidence': 'MEDIUM',
                    'description': f"Variable '{sym.name}' used without initialization"
                })

        return issues

    def _simple_analysis(self, code: str, filepath: str) -> List[Dict]:
        """
        Fallback: simple text-based analysis when AST parsing fails

        Still detects common patterns without full semantic analysis
        """
        issues = []

        # NULL dereference patterns
        if '->' in code and 'if' not in code[:code.index('->') if '->' in code else 0]:
            issues.append({
                'type': 'null-pointer-deref',
                'location': filepath,
                'code': 'ptr->field without NULL check',
                'confidence': 'LOW',
                'description': 'Potential NULL dereference (simple pattern match)'
            })

        # Buffer overflow patterns
        for func in ['strcpy', 'gets', 'sprintf']:
            if func in code:
                issues.append({
                    'type': 'buffer-overflow',
                    'function': func,
                    'location': filepath,
                    'code': f'Found call to {func}',
                    'confidence': 'MEDIUM',
                    'description': f'Dangerous function {func} without bounds checking'
                })

        return issues

    def get_symbol_table(self) -> SymbolTable:
        """Get current symbol table"""
        return self.symbol_table


# Export
__all__ = ['SemanticAnalyzer']


# Example usage
if __name__ == "__main__":
    analyzer = SemanticAnalyzer()

    # Test code
    test_code = """
    void process(int *data) {
        int x = data[0];  // Potential NULL dereference
        strcpy(buf, input);  // Buffer overflow
        free(ptr);
        ptr->field = 5;  // Use after free
    }
    """

    vulns = analyzer.analyze(test_code)
    print(f"Found {len(vulns)} vulnerabilities:\n")
    for v in vulns:
        print(f"  [{v['type']}] {v['description']}")
        print(f"    Location: {v['location']}")
        print(f"    Confidence: {v['confidence']}\n")
