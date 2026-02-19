"""
DrCov format parser

From the Lighthouse Plugin
By Markus Gaasedelen @gaasedelen
"""

import os
import sys
import struct
import re
from ctypes import *
import io
from typing import List, Optional
import argparse

from base import CoverageParser, ParsedModule, ParsedBasicBlock


class DrcovParser(CoverageParser):
    """
    DrCov log parser implementing the CoverageParser interface.
    """

    def __init__(self, filepath=None, data=None):
        super().__init__(filepath, data)
        
        # drcov header attributes
        self.version = 0
        self.flavor = None

        # drcov module table
        self.module_table_count = 0
        self.module_table_version = 0
        self._raw_modules = []  # Internal DrcovModule objects
        self._parsed_modules = []  # Converted ParsedModule objects

        # drcov basic block data
        self.bb_table_count = 0
        self.bb_table_is_binary = True
        self._raw_basic_blocks = []  # Internal DrcovBasicBlock ctypes array
        self._parsed_basic_blocks = []  # Converted ParsedBasicBlock objects

        # drcov aggregated data
        self.bb_hit_count_map = {}

        # Parse automatically on initialization
        self.parse()

    def parse(self) -> None:
        """Parse the coverage data."""
        if self._parsed:
            return
            
        if self.filepath is not None:
            self._parse_drcov_file(self.filepath)
        elif self.data is not None:
            self._parse_drcov_data(self.data)
            
        # Convert internal objects to clean parsed objects
        self._convert_to_parsed_objects()
        self._mark_parsed()

    def get_modules(self) -> List[ParsedModule]:
        """Get list of modules from coverage data."""
        return self._parsed_modules

    def get_basic_blocks(self) -> List[ParsedBasicBlock]:
        """Get list of basic blocks from coverage data."""
        return self._parsed_basic_blocks

    def get_module(self, module_name: str, fuzzy: bool = True) -> Optional[ParsedModule]:
        """
        Get a module by its name.

        Args:
            module_name: Name of the module to find
            fuzzy: Whether to perform fuzzy lookup (case-insensitive, partial matches)
            
        Returns:
            ParsedModule if found, None otherwise
        """

        # fuzzy module name lookup
        if fuzzy:
            # attempt lookup using case-insensitive filename
            for module in self._parsed_modules:
                if module_name.lower() in module.filename.lower():
                    return module

            # no hits yet... let's cleave the extension from the given module
            # name (if present) and try again
            if "." in module_name:
                module_name = module_name.split(".")[0]

            # attempt lookup using case-insensitive filename without extension
            for module in self._parsed_modules:
                if module_name.lower() in module.filename.lower():
                    return module

        # strict lookup
        else:
            for module in self._parsed_modules:
                if module_name == module.filename:
                    return module

        # no matching module exists
        return None

    def get_blocks_by_module(self, module_name: str) -> List[ParsedBasicBlock]:
        """
        Extract coverage blocks pertaining to the named module.
        
        Args:
            module_name: Name of the module to get blocks for
            
        Returns:
            List of basic blocks for the specified module
            
        Raises:
            ValueError: If module is not found
        """

        # locate the coverage that matches the given module_name
        module = self.get_module(module_name)

        # if we fail to find a module that matches the given name, bail
        if not module:
            raise ValueError("No coverage for module '%s' in log" % module_name)

        # extract module id for speed
        mod_id = module.id

        # loop through the coverage data and filter out data for only this module
        coverage_blocks = [bb for bb in self._parsed_basic_blocks if bb.mod_id == mod_id]

        # return the filtered coverage blocks
        return coverage_blocks

    def get_hit_count_map_by_module(self, module_name: str):
        """Get hit count map for a specific module."""
        # locate the coverage that matches the given module_name
        module = self.get_module(module_name)

        # if we fail to find a module that matches the given name, bail
        if not module:
            raise ValueError("No coverage for module '%s' in log" % module_name)

        # extract module id for speed
        mod_id = module.id

        # loop through the coverage data and filter out data for only this module
        bb_hit_count_map = [(bb_start, self.bb_hit_count_map[mod_id][bb_start]) for bb_start in self.bb_hit_count_map[mod_id]]

        # return the filtered coverage blocks
        return bb_hit_count_map

    # --------------------------------------------------------------------------
    # Parsing Routines - Top Level
    # --------------------------------------------------------------------------

    def _parse_drcov_file(self, filepath):
        """Parse drcov coverage from the given log file."""
        with open(filepath, "rb") as f:
            self._parse_drcov_header(f)
            self._parse_module_table(f)
            self._parse_bb_table(f)
            self._generate_bb_hit_count_map()

    def _parse_drcov_data(self, drcov_data):
        """Parse drcov coverage from the given data blob."""
        with io.BytesIO(drcov_data) as f:
            self._parse_drcov_header(f)
            self._parse_module_table(f)
            self._parse_bb_table(f)
            self._generate_bb_hit_count_map()

    # --------------------------------------------------------------------------
    # Parsing Routines - Internals
    # --------------------------------------------------------------------------

    def _parse_drcov_header(self, f):
        """Parse drcov log header from filestream."""
        # parse drcov version from log
        #   eg: DRCOV VERSION: 2
        version_line = f.readline().strip()
        print(version_line)
        self.version = int(version_line.split(b":")[1])

        # parse drcov flavor from log
        #   eg: DRCOV FLAVOR: drcov
        flavor_line = f.readline().strip()
        self.flavor = flavor_line.split(b":")[1]

        assert self.version == 2, "Only drcov version 2 log files supported"

    def _parse_module_table(self, f):
        """Parse drcov log module table from filestream."""
        self._parse_module_table_header(f)
        self._parse_module_table_columns(f)
        self._parse_module_table_modules(f)

    def _parse_module_table_header(self, f):
        """Parse drcov log module table header from filestream."""
        # parse module table 'header'
        #   eg: Module Table: version 2, count 11
        header_line = f.readline().strip()
        field_name, field_data = header_line.split(b": ")

        # NOTE/COMPAT: DynamoRIO doesn't document their drcov log format, and it has
        # changed its format at least once during its lifetime.
        try:
            # seperate 'version X' and 'count Y' from each other ('v2')
            version_data, count_data = field_data.split(b", ")
        # failure to unpack indicates this is an 'older, v1' drcov log
        except ValueError:
            self.module_table_count = int(field_data)
            self.module_table_version = 1
            return

        # parse module table version out of 'version X'
        data_name, version = version_data.split(b" ")
        self.module_table_version = int(version)
        if not self.module_table_version in [2, 3, 4]:
            raise ValueError("Unsupported (new?) drcov log format...")

        # parse module count in table from 'count Y'
        data_name, count = count_data.split(b" ")
        self.module_table_count = int(count)

    def _parse_module_table_columns(self, f):
        """Parse drcov log module table columns from filestream."""
        # NOTE/COMPAT: there is no 'Columns' line for the v1 table...
        if self.module_table_version == 1:
            return

        # parse module table 'columns'
        #   eg: Columns: id, base, end, entry, checksum, timestamp, path
        column_line = f.readline().strip()
        field_name, field_data = column_line.split(b": ")

        # seperate column names
        #   Windows:   id, base, end, entry, checksum, timestamp, path
        #   Mac/Linux: id, base, end, entry, path
        columns = field_data.split(b", ")

    def _parse_module_table_modules(self, f):
        """Parse drcov log modules in the module table from filestream."""
        # loop through each *expected* line in the module table and parse it
        for i in range(0, self.module_table_count):
            module = DrcovModule(f.readline().strip(), self.module_table_version)
            self._raw_modules.append(module)

    def _parse_bb_table(self, f):
        """Parse dcov log basic block table from filestream."""
        self._parse_bb_table_header(f)
        self._parse_bb_table_entries(f)

    def _parse_bb_table_header(self, f):
        """Parse drcov log basic block table header from filestream."""
        # parse basic block table 'header'
        #   eg: BB Table: 2792 bbs
        header_line = f.readline().strip()
        field_name, field_data = header_line.split(b": ")

        # parse basic block count out of 'X bbs'
        count_data, data_name = field_data.split(b" ")
        self.bb_table_count = int(count_data)

        # peek at the next few bytes to determine if this is a binary bb table.
        # An ascii bb table will have the line: 'module id, start, size:'
        token = "module id"
        saved_position = f.tell()

        # is this an ascii table?
        if f.read(len(token)) == token:
            self.bb_table_is_binary = False
        # nope! binary table
        else:
            self.bb_table_is_binary = True

        # seek back to the start of the table
        f.seek(saved_position)

    def _parse_bb_table_entries(self, f):
        """Parse drcov log basic block table entries from filestream."""
        # allocate the ctypes structure array of basic blocks
        self._raw_basic_blocks = (DrcovBasicBlock * self.bb_table_count)()

        if self.bb_table_is_binary:
            # read the basic block entries directly into the newly allocated array
            f.readinto(self._raw_basic_blocks)
        else:  # let's parse the text records
            text_entry = f.readline().strip()

            if text_entry != "module id, start, size:":
                raise ValueError("Invalid BB header: %r" % text_entry)

            pattern = re.compile(r"^module\[\s*(?P<mod>[0-9]+)\]\:\s*(?P<start>0x[0-9a-f]+)\,\s*(?P<size>[0-9]+)$")
            for basic_block in self._raw_basic_blocks:
                text_entry = f.readline().strip()

                match = pattern.match(text_entry)
                if not match:
                    raise ValueError("Invalid BB entry: %r" % text_entry)

                basic_block.offset = int(match.group("start"), 16)
                basic_block.size = int(match.group("size"), 10)
                basic_block.mod_id = int(match.group("mod"), 10)

    def _generate_bb_hit_count_map(self):
        """Generate basic block hit count map."""
        for bb in self._raw_basic_blocks:
            mod_id = bb.mod_id
            if mod_id not in self.bb_hit_count_map:
                self.bb_hit_count_map[mod_id] = {}
            if bb.offset in self.bb_hit_count_map[mod_id]:
                self.bb_hit_count_map[mod_id][bb.offset] += 1
            else:
                self.bb_hit_count_map[mod_id][bb.offset] = 1

    def _convert_to_parsed_objects(self):
        """Convert internal ctypes objects to clean ParsedModule and ParsedBasicBlock objects."""
        # Convert modules
        self._parsed_modules = []
        for raw_module in self._raw_modules:
            parsed_module = ParsedModule(
                id=raw_module.id,
                filename=raw_module.filename,
                base=raw_module.base,
                end=raw_module.end,
                size=raw_module.size,
                checksum=raw_module.checksum,
                path=raw_module.path,
                entry=raw_module.entry
            )
            self._parsed_modules.append(parsed_module)

        # Convert basic blocks
        self._parsed_basic_blocks = []
        for raw_bb in self._raw_basic_blocks:
            parsed_bb = ParsedBasicBlock(
                offset=raw_bb.offset,
                size=raw_bb.size,
                mod_id=raw_bb.mod_id
            )
            self._parsed_basic_blocks.append(parsed_bb)

    # Legacy property accessors for backward compatibility
    @property
    def modules(self):
        """Legacy accessor - returns raw modules for backward compatibility."""
        return self._raw_modules

    @property
    def basic_blocks(self):
        """Legacy accessor - returns raw basic blocks for backward compatibility."""
        return self._raw_basic_blocks


# Legacy alias for backward compatibility
DrcovData = DrcovParser


# ------------------------------------------------------------------------------
# drcov module parser
# ------------------------------------------------------------------------------

class DrcovModule(object):
    """
    Parser & wrapper for module details as found in a drcov coverage log.

    A 'module' in this context is a .EXE, .DLL, ELF, MachO, etc.
    """

    def __init__(self, module_data, version):
        self.id = 0
        self.base = 0
        self.end = 0
        self.size = 0
        self.entry = 0
        self.checksum = 0
        self.timestamp = 0
        self.path = ""
        self.filename = ""
        self.containing_id = 0

        # parse the module
        self._parse_module(module_data, version)

    @property
    def start(self):
        """
        Compatability alias for the module base.

        DrCov table version 2 --> 3 changed this paramter name base --> start.
        """
        return self.base

    def _parse_module(self, module_line, version):
        """Parse a module table entry."""
        data = module_line.split(b", ")

        # NOTE/COMPAT
        if version == 1:
            self._parse_module_v1(data)
        elif version == 2:
            self._parse_module_v2(data)
        elif version == 3:
            self._parse_module_v3(data)
        elif version == 4:
            self._parse_module_v4(data)
        else:
            raise ValueError("Unknown module format (v%u)" % version)

    def _parse_module_v1(self, data):
        """Parse a module table v1 entry."""
        self.id = int(data[0])
        self.size = int(data[1])
        self.path = data[2].decode()
        self.filename = os.path.basename(self.path).strip("'")

    def _parse_module_v2(self, data):
        """Parse a module table v2 entry."""
        self.id = int(data[0])
        self.base = int(data[1], 16)
        self.end = int(data[2], 16)
        self.entry = int(data[3], 16)
        if len(data) == 7:  # Windows Only
            self.checksum = int(data[4], 16)
            self.timestamp = int(data[5], 16)
        self.path = data[-1].decode()
        self.size = self.end - self.base
        self.filename = os.path.basename(self.path).strip("'")

    def _parse_module_v3(self, data):
        """Parse a module table v3 entry."""
        self.id = int(data[0])
        self.containing_id = int(data[1])
        self.base = int(data[2], 16)
        self.end = int(data[3], 16)
        self.entry = int(data[4], 16)
        if len(data) == 7:  # Windows Only
            self.checksum = int(data[5], 16)
            self.timestamp = int(data[6], 16)
        self.path = data[-1].decode()
        self.size = self.end - self.base
        self.filename = os.path.basename(self.path).strip("'")

    def _parse_module_v4(self, data):
        """Parse a module table v4 entry."""
        self.id = int(data[0])
        self.containing_id = int(data[1])
        self.base = int(data[2], 16)
        self.end = int(data[3], 16)
        self.entry = int(data[4], 16)
        self.offset = int(data[5], 16)
        if len(data) == 7:  # Windows Only
            self.checksum = int(data[6], 16)
            self.timestamp = int(data[7], 16)
        self.path = data[-1].decode()
        self.size = self.end - self.base
        self.filename = os.path.basename(self.path).strip("'")


# ------------------------------------------------------------------------------
# drcov basic block parser
# ------------------------------------------------------------------------------

class DrcovBasicBlock(Structure):
    """
    Parser & wrapper for basic block details as found in a drcov coverage log.

    NOTE:

      Based off the C structure as used by drcov -

        /* Data structure for the coverage info itself */
        typedef struct _bb_entry_t {
            uint   offset;      /* offset of bb start from the image base */
            ushort size;
            ushort mod_id;
        } bb_entry_t;

    """
    _pack_ = 1
    _fields_ = [
        ('offset', c_uint32),
        ('size', c_uint16),
        ('mod_id', c_uint16),
    ]


# ------------------------------------------------------------------------------
# Command Line Testing
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    argparse = argparse.ArgumentParser(description="DrCov log parser test harness")
    argparse.add_argument("--input", "-i", help="Path to the drcov file to parse")
    argparse.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    argv = argparse.parse_args()

    # attempt file parse
    x = DrcovParser(argv.input)
    modules = x.modules
    for module in modules:
        print(f"Module {module.id}: {module.filename} @ {hex(module.base)}-{hex(module.end)}")
        blocks = x.get_blocks_by_module(module.filename)
        print(f"  Basic Blocks: {len(blocks)}")
        if argv.verbose:
            for block in blocks:
                print(f"    Block @ {hex(block.offset)} of size {block.size}")
