"""
Symbol Table
Tracks variables, functions, types across scopes
"""

from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum


class SymbolType(Enum):
    """Type of symbol"""
    VARIABLE = "var"
    FUNCTION = "func"
    POINTER = "ptr"
    ARRAY = "arr"
    STRUCT = "struct"


@dataclass
class Symbol:
    """Represents a variable/function/type in the code"""
    name: str
    type_str: str              # "int", "char*", "void*", etc.
    scope_level: int           # 0=global, 1+=local
    declared_at: Tuple[str, int]  # (file, line)
    symbol_type: SymbolType = SymbolType.VARIABLE

    # Usage tracking
    assigned_at: List[Tuple[str, int]] = field(default_factory=list)
    dereferenced_at: List[Tuple[str, int]] = field(default_factory=list)
    freed_at: Optional[Tuple[str, int]] = None

    # Safety checks
    is_null_checked: bool = False
    has_bounds_check: bool = False
    initialized: bool = False

    def is_pointer(self) -> bool:
        """Check if this symbol is a pointer type"""
        return '*' in self.type_str or self.symbol_type == SymbolType.POINTER

    def is_array(self) -> bool:
        """Check if this symbol is an array type"""
        return '[' in self.type_str or self.symbol_type == SymbolType.ARRAY

    def __repr__(self):
        return f"Symbol({self.name}: {self.type_str})"


class SymbolTable:
    """
    Symbol table tracks all symbols (variables, functions) across scopes
    """

    def __init__(self):
        """Initialize symbol table"""
        # Stack of scopes: scopes[0]=global, scopes[1]=outer function, etc.
        self.scopes: List[Dict[str, Symbol]] = [{}]
        self.scope_level = 0

        # Global lookups
        self.all_symbols: Dict[str, Symbol] = {}
        self.functions: Dict[str, Symbol] = {}

    def enter_scope(self):
        """Enter new scope (function, block)"""
        self.scope_level += 1
        self.scopes.append({})

    def exit_scope(self):
        """Exit current scope"""
        if self.scope_level > 0:
            del self.scopes[self.scope_level]
            self.scope_level -= 1

    def declare_symbol(
        self,
        name: str,
        type_str: str,
        location: Tuple[str, int],
        symbol_type: SymbolType = SymbolType.VARIABLE
    ) -> Symbol:
        """
        Declare a new symbol in current scope

        Args:
            name: Variable/function name
            type_str: Type string (e.g., "int*", "char")
            location: (file, line) where declared
            symbol_type: Type of symbol

        Returns:
            Created Symbol
        """
        # Detect pointer/array from type_str
        if '*' in type_str:
            symbol_type = SymbolType.POINTER
        elif '[' in type_str:
            symbol_type = SymbolType.ARRAY

        sym = Symbol(
            name=name,
            type_str=type_str,
            scope_level=self.scope_level,
            declared_at=location,
            symbol_type=symbol_type
        )

        # Add to current scope
        self.scopes[self.scope_level][name] = sym

        # Add to global registry
        self.all_symbols[name] = sym

        # Track functions separately
        if symbol_type == SymbolType.FUNCTION:
            self.functions[name] = sym

        return sym

    def lookup_symbol(self, name: str) -> Optional[Symbol]:
        """
        Find symbol in current or parent scopes

        Searches from current scope up to global scope

        Args:
            name: Symbol name

        Returns:
            Symbol if found, None otherwise
        """
        # Search from current scope upward
        for level in range(self.scope_level, -1, -1):
            if name in self.scopes[level]:
                return self.scopes[level][name]

        return None

    def mark_null_checked(self, name: str, location: Tuple[str, int]):
        """
        Mark that a pointer was checked against NULL

        Args:
            name: Variable name
            location: Where NULL check occurred
        """
        sym = self.lookup_symbol(name)
        if sym and sym.is_pointer():
            sym.is_null_checked = True

    def mark_bounds_checked(self, name: str, location: Tuple[str, int]):
        """
        Mark that an array/buffer had bounds check

        Args:
            name: Variable name
            location: Where bounds check occurred
        """
        sym = self.lookup_symbol(name)
        if sym:
            sym.has_bounds_check = True

    def mark_freed(self, name: str, location: Tuple[str, int]):
        """
        Mark that a pointer was freed

        Args:
            name: Variable name
            location: Where free occurred
        """
        sym = self.lookup_symbol(name)
        if sym and sym.is_pointer():
            sym.freed_at = location

    def mark_assigned(self, name: str, location: Tuple[str, int]):
        """
        Track assignment location

        Args:
            name: Variable name
            location: Where assigned
        """
        sym = self.lookup_symbol(name)
        if sym:
            sym.assigned_at.append(location)
            sym.initialized = True

    def mark_dereferenced(self, name: str, location: Tuple[str, int]):
        """
        Track dereference location (ptr->field or ptr[i])

        Args:
            name: Variable name
            location: Where dereferenced
        """
        sym = self.lookup_symbol(name)
        if sym:
            sym.dereferenced_at.append(location)

    def get_all_symbols(self) -> List[Symbol]:
        """Get all declared symbols"""
        return list(self.all_symbols.values())

    def get_uninitialized_symbols(self) -> List[Symbol]:
        """Find symbols that were declared but never initialized"""
        return [s for s in self.all_symbols.values() if not s.initialized]

    def get_unused_symbols(self) -> List[Symbol]:
        """Find symbols that were declared but never used"""
        return [
            s for s in self.all_symbols.values()
            if not s.dereferenced_at and not s.freed_at
        ]

    def get_unsafe_pointers(self) -> List[Symbol]:
        """Find pointers that:
        - Were dereferenced without NULL check, OR
        - Were freed but still used
        """
        unsafe = []

        for sym in self.all_symbols.values():
            if not sym.is_pointer():
                continue

            # Dereferenced without NULL check
            if sym.dereferenced_at and not sym.is_null_checked:
                unsafe.append(sym)

            # Use after free
            if sym.freed_at:
                # Check if used after free
                if sym.freed_at < sym.dereferenced_at[-1] if sym.dereferenced_at else False:
                    unsafe.append(sym)

        return unsafe

    def get_buffer_overflows(self) -> List[Symbol]:
        """Find arrays/buffers that might overflow"""
        overflows = []

        for sym in self.all_symbols.values():
            if sym.is_array() and not sym.has_bounds_check:
                # Array without bounds checking
                overflows.append(sym)

        return overflows

    def __repr__(self):
        lines = [f"SymbolTable (scope level: {self.scope_level})"]
        for level, scope in enumerate(self.scopes):
            lines.append(f"  Scope {level}: {list(scope.keys())}")
        return '\n'.join(lines)


# Example usage
if __name__ == "__main__":
    st = SymbolTable()

    # Declare some symbols
    st.declare_symbol("buf", "char[10]", ("test.c", 1))
    st.declare_symbol("ptr", "int*", ("test.c", 2))
    st.declare_symbol("x", "int", ("test.c", 3))

    # Mark operations
    st.mark_assigned("ptr", ("test.c", 4))
    st.mark_null_checked("ptr", ("test.c", 5))
    st.mark_dereferenced("ptr", ("test.c", 6))

    print(st)

    # Check for unsafe accesses
    print(f"\nUnsafe pointers: {st.get_unsafe_pointers()}")
    print(f"Buffer overflows: {st.get_buffer_overflows()}")
