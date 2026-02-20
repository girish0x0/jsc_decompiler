#!/usr/bin/env python3
"""
JSC Decompiler - Standalone V8 bytecode disassembler for .jsc files
Ported from ghidra_nodejs (Java/Ghidra plugin)

Supports:
  - V8 5.x-8.x (Node 8-10): Native binary parser
"""

import argparse
import struct
import sys
import os

from common.version import V8VersionDetector
from v6.parser import JscParser
from v6.structs import SharedFunctionInfo
from output_formatter import (
    format_output, format_json_output, format_js_output,
)


# V8 magic bytes
_MAGIC_V8_LEGACY = (0xC0DE0BEE, 0xC0DE03BE)  # V8 5.x-8.x
_MAGIC_V8_MODERN = (0xC0DE0628,)                # V8 12.x (Node 22+)
_ALL_MAGIC = _MAGIC_V8_LEGACY + _MAGIC_V8_MODERN


def _run_legacy_pipeline(args, data):
    """Handle V8 5.x-8.x JSC files via native binary parser."""
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    detector = V8VersionDetector(data_dir)

    version_hash = struct.unpack_from("<I", data, 4)[0]
    version = detector.detect_version(version_hash)

    try:
        is_32bit = detector.detect_bitness(version_hash)
    except ValueError:
        if not args.quiet:
            print("Warning: Unknown version hash 0x%08X, assuming 64-bit" % version_hash, file=sys.stderr)
        is_32bit = False

    if not args.quiet and not args.json:
        print("Parsing %s..." % os.path.basename(args.file), file=sys.stderr)
        print("V8 Version: %s (%s)" % (version, "32-bit" if is_32bit else "64-bit"), file=sys.stderr)

    # Parse
    jsc_parser = JscParser(data, is_32bit)
    jsc_parser.load_metadata(data_dir)

    try:
        func_objects = jsc_parser.parse()
    except Exception as e:
        print("Error parsing JSC file: %s" % e, file=sys.stderr)
        if not args.quiet:
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    if not func_objects:
        if not args.quiet:
            print("No functions found in JSC file.", file=sys.stderr)
        sys.exit(0)

    # Convert to SharedFunctionInfo structs
    if not args.quiet and not args.json:
        print("Converting %d function objects..." % len(func_objects), file=sys.stderr)

    scope_cache = {}
    functions = []
    for func_obj in func_objects:
        try:
            sfi = SharedFunctionInfo(func_obj, jsc_parser.kPointerSize, scope_cache)
            functions.append(sfi)
        except Exception as e:
            if not args.quiet:
                print("Warning: Failed to parse function: %s" % e, file=sys.stderr)

    if not args.quiet and not args.json and not args.js:
        print("Extracted %d functions." % len(functions), file=sys.stderr)

    # Output
    if args.json:
        print(format_json_output(version, is_32bit, functions))
    elif args.js:
        print(format_js_output(version, is_32bit, functions, os.path.basename(args.file)))
    else:
        print(format_output(version, is_32bit, functions, verbose=args.verbose))


def main():
    parser = argparse.ArgumentParser(
        description="V8 JSC bytecode disassembler (supports Node 8)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Decompile to JavaScript (default)
  python3 jsc_decompiler.py sample.jsc

  # Raw disassembly output
  python3 jsc_decompiler.py sample.jsc --disasm

  # JSON output
  python3 jsc_decompiler.py sample.jsc -j"""
    )
    parser.add_argument("file", help="Path to .jsc file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show constant pools and handler tables")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output in JSON format")
    parser.add_argument("--js", action="store_true", default=True,
                        help="Output reconstructed JavaScript pseudo-code (default)")
    parser.add_argument("--disasm", action="store_true",
                        help="Output raw disassembly instead of JavaScript")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress progress messages")
    args = parser.parse_args()

    # --json or --disasm override the default --js
    if args.json or args.disasm:
        args.js = False

    if not os.path.isfile(args.file):
        print("Error: File not found: %s" % args.file, file=sys.stderr)
        sys.exit(1)

    with open(args.file, "rb") as f:
        data = f.read()

    if len(data) < 8:
        print("Error: File too small", file=sys.stderr)
        sys.exit(1)

    # Check magic
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in _ALL_MAGIC:
        print("Error: Invalid JSC magic: 0x%08X" % magic, file=sys.stderr)
        sys.exit(1)

    # Route based on JSC format version
    if magic in _MAGIC_V8_MODERN:
        print("Error: This file was compiled with Node.js 22+ (V8 12.x).", file=sys.stderr)
        print("Node 22 support is available separately.", file=sys.stderr)
        print("Contact: Girishx3@gmail.com", file=sys.stderr)
        sys.exit(1)
    else:
        _run_legacy_pipeline(args, data)


if __name__ == "__main__":
    main()
