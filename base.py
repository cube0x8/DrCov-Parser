"""
Base parser interface for coverage data.

Provides an abstract base class that all coverage format parsers must implement.
This enables the system to support multiple coverage formats (DrCov, gcov, llvm-cov, etc.)
in a consistent and extensible way.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Any


class CoverageParser(ABC):
    """
    Abstract base class for all coverage parsers.
    
    All coverage format parsers (DrCov, gcov, etc.) must inherit from this class
    and implement the required abstract methods. This ensures a consistent interface
    that the CoverageManager can use regardless of the underlying format.
    """
    
    def __init__(self, filepath: Optional[str] = None, data: Optional[bytes] = None):
        """
        Initialize parser with either a file path or raw data.
        
        Args:
            filepath: Path to coverage file (mutually exclusive with data)
            data: Raw coverage data as bytes (mutually exclusive with filepath)
            
        Raises:
            ValueError: If both or neither filepath and data are provided
        """
        if (filepath is None and data is None) or (filepath is not None and data is not None):
            raise ValueError("Provide either filepath or data, not both or neither")
            
        self.filepath = filepath
        self.data = data
        self._parsed = False
    
    @abstractmethod
    def parse(self) -> None:
        """
        Parse the coverage data.
        
        This method should parse the coverage file/data and populate internal
        data structures. Must be called before other methods can be used.
        """
        pass
    
    @abstractmethod
    def get_modules(self) -> List[Any]:
        """
        Get list of modules from parsed coverage data.
        
        Returns:
            List of parsed module objects
        """
        pass
    
    @abstractmethod
    def get_basic_blocks(self) -> List[Any]:
        """
        Get list of all basic blocks from parsed coverage data.
        
        Returns:
            List of parsed basic block objects
        """
        pass
    
    @abstractmethod
    def get_blocks_by_module(self, module_name: str) -> List[Any]:
        """
        Get basic blocks for a specific module.
        
        Args:
            module_name: Name of the module to get blocks for
            
        Returns:
            List of basic blocks for the specified module
            
        Raises:
            ValueError: If module is not found
        """
        pass
    
    @abstractmethod
    def get_module(self, module_name: str, fuzzy: bool = True) -> Optional[Any]:
        """
        Get module by name.
        
        Args:
            module_name: Name of the module to find
            fuzzy: Whether to perform fuzzy matching (case-insensitive, partial matches)
            
        Returns:
            Module object if found, None otherwise
        """
        pass
    
    def is_parsed(self) -> bool:
        """Check if the coverage data has been parsed."""
        return self._parsed
    
    def _mark_parsed(self) -> None:
        """Mark the coverage data as parsed (for use by subclasses)."""
        self._parsed = True


class ParsedModule:
    """
    Standard representation of a parsed module.
    
    Provides a clean interface for modules regardless of the original
    coverage format.
    """
    
    def __init__(self, id: int, filename: str, base: int, end: int, size: int, 
                 checksum: int = 0, path: str = "", entry: int = 0):
        self.id = id
        self.filename = filename
        self.base = base
        self.end = end
        self.size = size
        self.checksum = checksum
        self.path = path
        self.entry = entry

    @property
    def start(self):
        """Compatibility alias for base address."""
        return self.base

    def __repr__(self):
        return f"ParsedModule(id={self.id}, filename='{self.filename}', base=0x{self.base:x}, size={self.size})"


class ParsedBasicBlock:
    """
    Standard representation of a parsed basic block.
    
    Provides a clean interface for basic blocks regardless of the original
    coverage format.
    """
    
    def __init__(self, offset: int, size: int, mod_id: int):
        self.offset = offset
        self.size = size
        self.mod_id = mod_id

    def __repr__(self):
        return f"ParsedBasicBlock(offset=0x{self.offset:x}, size={self.size}, mod_id={self.mod_id})"