# jsc_decompiler

Decompile V8 bytecode (`.jsc` / Bytenode) files back into readable JavaScript. Pure Python, no dependencies.

Supports **Node.js 8** (V8 6.2).

## Quick Start

```bash
git clone https://github.com/girish0x0/jsc_decompiler.git
cd jsc_decompiler

# Decompile a .jsc file to JavaScript (default output)
python3 jsc_decompiler.py app.jsc

# Raw disassembly output
python3 jsc_decompiler.py app.jsc --disasm

# JSON output
python3 jsc_decompiler.py app.jsc -j

# Verbose (show constant pools, handler tables)
python3 jsc_decompiler.py app.jsc --disasm -v
```

## Example

**Original source** (before compilation):
```javascript
function greet(name) {
    return "Hello, " + name + "!";
}

function factorial(n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}
```

**Decompiled output** from the `.jsc` bytecode:
```javascript
function greet(a0) {
    return ("Hello, " + a0) + "!";
}

function factorial(a0) {
    if (a0 <= 1) {
        return 1;
    }

    return a0 * factorial((a0 - 1));
}
```

Variable names are lost during compilation (replaced with `a0`, `a1` for parameters, `r0`, `r1` for locals), but the logic and structure are fully recovered.

## What It Can Decompile

| Feature | Status |
|---------|--------|
| Functions, parameters, closures | Supported |
| if/else, ternary | Supported |
| while, do-while, for | Supported |
| for-in, for-of | Supported |
| switch/case | Supported |
| try-catch-finally | Supported |
| Classes (DefineClass) | Supported |
| async/await | Supported |
| Generators (function*) | Supported |
| Spread, rest, destructuring | Partial |
| Arrow functions | Shown as regular functions |
| Inner functions (lazy-compiled) | Requires `--no-lazy` flag during compilation |

## Additional V8 Version Support

The following versions are available separately:

| Node.js | Electron | V8 Engine | Highlights |
|---------|----------|-----------|------------|
| 16.x | 17–25 | 9.4 / 9.8 | Native binary parser, iterative closure inlining for deep webpack bundles, nested array boilerplate extraction |
| 22.x | — | 12.4 | Full decompilation with async/await, generators, optional chaining, nullish coalescing |

Contact **Girishx3@gmail.com** for access.

## How .jsc Files Are Created

`.jsc` files are typically created using [Bytenode](https://www.npmjs.com/package/bytenode) or V8's code cache API:

```javascript
// Using Bytenode
const bytenode = require('bytenode');
bytenode.compileFile('app.js', 'app.jsc');

// Using V8 directly
const v8 = require('v8');
v8.setFlagsFromString('--no-lazy');
const code = require('fs').readFileSync('app.js', 'utf8');
const cached = new vm.Script(code).createCachedData();
require('fs').writeFileSync('app.jsc', cached);
```

Use `--no-lazy` when compiling to ensure inner functions are included in the bytecode. Without it, inner functions are lazy-compiled and won't have bytecode available in the `.jsc` file.

## Disassembly Output

The `--disasm` flag shows raw V8 bytecode with annotations:

```
Function: greet
----------------------------------------------------------------------
  Parameters: 2    Registers: 1
  Bytecode:
    0000: 13 00                    LdaConstant [0]              ; "Hello, "
    0002: 35 02 00                 Add a0 [0]
    0005: C9                       Star0
    0006: 13 01                    LdaConstant [1]              ; "!"
    0008: 35 F9 02                 Add r0 [2]
    000B: AA                       Return
```

## Supported V8 Versions

| Node.js | V8 Engine | Architecture | Status |
|---------|-----------|-------------|--------|
| 8.16.0 | 6.2.414.77 | x64, x86 | Full support |

V8 version is auto-detected from the binary header hash.

## Project Structure

```
jsc_decompiler.py          # CLI entry point
reconstructor.py           # JS reconstruction engine
output_formatter.py        # Output formatting (text/JSON/JS)
v6/                        # Node 8 / V8 6.x pipeline
    parser.py              #   Binary parser
    disasm.py              #   Bytecode disassembler (169 opcodes)
    structs.py             #   SharedFunctionInfo, ScopeInfo structs
common/                    # Shared utilities
    version.py             #   Version detection via hash matching
    enums.py               #   V8 enum definitions
data/                      # V8 metadata (builtins, roots, versions)
samples/                   # Sample .jsc files
tests/                     # Test fixtures
```

## Acknowledgments

The V8 6.x parser was originally ported from [ghidra_nodejs](https://github.com/PositiveTechnologies/ghidra_nodejs) (Positive Technologies).

## License

[MIT](LICENSE)
