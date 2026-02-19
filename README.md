# DrCOV Parser

A parser for analyzing DrCov code coverage files. The code has been isolated from the Lighthouse Plugin by Markus Gaasedelen (@gaasedelen) and re-adapted into a standalone tool.

## What it does

The parser:
- **Reads and decompresses** drcov files (including those compressed with gzip)
- **Analyzes coverage data** extracted from instrumented program executions
- **Organizes information** into easily queryable data structures
- **Supports multiple versions** of the drcov format (v1, v2, v3, v4)

## Information it provides

For each drcov file, the parser extracts:

- **Modules**: List of binaries/libraries (EXE, DLL, ELF, MachO, etc.) analyzed with:
  - ID, base address, end address
  - Entry point, checksum, timestamp
  - Module path and filename
  
- **Basic Blocks**: Sequences of instructions executed with:
  - Offset from the module's base address
  - Size in bytes
  - Containing module
  - Hit count (number of times executed, in case of full-trace was specified during generation)

## How to use it

### Command line usage

```bash
# Show basic information as modules names and number of basic blocks for each module 
python drcov.py -i <path_to_drcov_file>
```

```bash
# Show basic module information and offset/size of each traced basic block
python drcov.py -i <path_to_drcov_file> --verbose
```

### Usage as a Python library

```python
from drcov import DrcovParser

# Load and analyze the file
parser = DrcovParser('coverage.drcov')

# Get all modules
modules = parser.get_modules()
for module in modules:
    print(f"Module: {module.filename} @ {hex(module.base)}")

# Get basic blocks for a specific module
blocks = parser.get_blocks_by_module('ceva_emu.cvd')
for block in blocks:
    print(f"Block at {hex(block.offset)}, size {block.size}")

# Get the hit count map for a module
hit_counts = parser.get_hit_count_map_by_module('ceva_emu.cvd')
for start_addr, count in hit_counts:
    print(f"{hex(start_addr)}: {count} hits")
```
