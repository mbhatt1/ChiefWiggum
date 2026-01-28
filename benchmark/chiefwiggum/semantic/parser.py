"""
C/C++ Parser using pycparser
Converts source code to Abstract Syntax Tree (AST)
"""

from pycparser import parse_file, c_ast, c_parser, c_generator
from typing import Optional, List
import re


class CParser:
    """Parse C code into Abstract Syntax Tree"""

    def __init__(self):
        """Initialize parser"""
        try:
            self.parser = c_parser.CParser()
            self.generator = c_generator.CGenerator()
        except Exception as e:
            print(f"Warning: pycparser not available: {e}")
            print("Install with: pip install pycparser")
            self.parser = None
            self.generator = None

    def parse_code(self, code: str) -> Optional[c_ast.FileAST]:
        """
        Parse C code string into AST

        Args:
            code: C source code as string

        Returns:
            pycparser AST or None if parse fails
        """
        if not self.parser:
            return None

        try:
            # Remove preprocessor directives (handles #include, #define, etc.)
            preprocessed = self._preprocess(code)

            # Parse
            ast = self.parser.parse(preprocessed, filename='<code>')
            return ast

        except Exception as e:
            print(f"Parse error: {e}")
            return None

    def parse_file(self, filepath: str) -> Optional[c_ast.FileAST]:
        """
        Parse C file

        Args:
            filepath: Path to .c or .h file

        Returns:
            pycparser AST or None if parse fails
        """
        if not self.parser:
            return None

        try:
            # Use cpp preprocessor
            ast = parse_file(filepath, use_cpp=True)
            return ast
        except Exception as e:
            print(f"Parse error in {filepath}: {e}")
            return None

    def _preprocess(self, code: str) -> str:
        """
        Preprocess code: remove directives pycparser can't handle

        Args:
            code: Raw C code

        Returns:
            Cleaned code suitable for pycparser
        """
        lines = []

        for line in code.split('\n'):
            stripped = line.strip()

            # Skip preprocessor directives (but keep important ones)
            if stripped.startswith('#'):
                # Keep typedef, struct, enum definitions by removing the #
                if 'typedef' in stripped or 'struct' in stripped or 'enum' in stripped:
                    # Extract the typedef/struct/enum part
                    match = re.search(r'(typedef|struct|enum)\s+(.*)', stripped[1:])
                    if match:
                        lines.append(match.group(0))
                continue

            lines.append(line)

        return '\n'.join(lines)

    def walk_ast(self, node: c_ast.Node) -> List[c_ast.Node]:
        """
        Walk AST in depth-first order

        Args:
            node: Starting AST node

        Returns:
            List of all nodes
        """
        nodes = [node]

        for child_name, child in node.children():
            if isinstance(child, list):
                for item in child:
                    nodes.extend(self.walk_ast(item))
            else:
                nodes.extend(self.walk_ast(child))

        return nodes

    def get_functions(self, ast: c_ast.FileAST) -> List[c_ast.FuncDef]:
        """Extract all function definitions from AST"""
        functions = []

        for node in self.walk_ast(ast):
            if isinstance(node, c_ast.FuncDef):
                functions.append(node)

        return functions

    def get_declarations(self, ast: c_ast.FileAST) -> List[c_ast.Decl]:
        """Extract all declarations from AST"""
        decls = []

        for node in self.walk_ast(ast):
            if isinstance(node, c_ast.Decl) and node.name:
                decls.append(node)

        return decls


# Example usage
if __name__ == "__main__":
    parser = CParser()

    # Test parse
    code = """
    void process(int *data) {
        if (data == NULL) return;
        int x = data[0];
    }
    """

    ast = parser.parse_code(code)
    if ast:
        print("✓ Code parsed successfully")
        ast.show()
    else:
        print("✗ Parse failed")
