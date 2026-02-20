"""V8 5.x-8.x (Node 8) decompiler pipeline."""
from v6.parser import JscParser
from v6.structs import SharedFunctionInfo
from v6.disasm import disassemble_bytecode
