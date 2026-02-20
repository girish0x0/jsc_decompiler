"""
V8 Bytecode -> JavaScript Pseudo-Code Reconstructor

Walks disassembled V8 bytecode instructions and produces approximate
JavaScript source code using symbolic expression tracking.
"""

import json
import os
import re

from v6.disasm import (
    disassemble_bytecode, kReg, kImm, kIdx, kUImm, kFlag8,
    kIntrinsicId, kRuntimeId, kRegRange, kRegPair, kRegTriple,
    TYPEOF_LITERALS,
)
from common.reserv_object import RootObject

# V8 12.4 renamed several opcodes. Map new names → old handler names
# so existing instruction dispatch works for both versions.
_OPCODE_ALIASES = {
    "GetNamedProperty": "LdaNamedProperty",
    "GetKeyedProperty": "LdaKeyedProperty",
    "GetNamedPropertyFromSuper": "LdaNamedProperty",  # similar handling
    "GetEnumeratedKeyedProperty": "LdaKeyedProperty",  # similar handling
    "SetNamedProperty": "StaNamedPropertySloppy",
    "DefineNamedOwnProperty": "StaNamedOwnProperty",
    "SetKeyedProperty": "StaKeyedPropertySloppy",
    "DefineKeyedOwnProperty": "StaKeyedPropertySloppy",
    "DefineKeyedOwnPropertyInLiteral": "StaDataPropertyInLiteral",
    "StaGlobal": "StaGlobalSloppy",
}

# --- Operator precedence (higher = tighter binding) ---
_P_COND = 4  # ternary ? :
_P_OR = 6
_P_XOR = 7
_P_AND = 8
_P_EQ = 9
_P_REL = 10
_P_SHIFT = 11
_P_ADD = 12
_P_MUL = 13
_P_EXP = 14
_P_ATOM = 100  # variable / literal / call — never needs wrapping

# Ops where (a OP b) OP c == a OP (b OP c), so right operand at same
# precedence never needs parens.
_RIGHT_ASSOC_SAFE = frozenset({'+', '*', '|', '&', '^'})

# Opcodes that produce call expressions (may need to be emitted as statements)
_CALL_OPCODES = frozenset({
    "CallProperty0", "CallProperty1", "CallProperty2",
    "CallProperty", "CallAnyReceiver",
    "CallUndefinedReceiver0", "CallUndefinedReceiver1", "CallUndefinedReceiver2",
    "CallUndefinedReceiver", "CallWithSpread",
    "CallRuntime", "CallJSRuntime", "InvokeIntrinsic",
    "Construct", "ConstructWithSpread",
})


def _wrap_left(acc, acc_prec, op_prec):
    """Wrap acc when it is the LEFT operand and the new op binds tighter."""
    if acc_prec < op_prec:
        return "(%s)" % acc
    return acc


def _wrap_right(acc, acc_prec, op_prec, op_str):
    """Wrap acc when it is the RIGHT operand."""
    if acc_prec < op_prec:
        return "(%s)" % acc
    if acc_prec == op_prec and op_str not in _RIGHT_ASSOC_SAFE:
        return "(%s)" % acc
    return acc


# --- JSRuntime name resolution ---

_JSRUNS = None  # lazy-loaded list from v8_jsruns.json


def _load_jsruns():
    global _JSRUNS
    if _JSRUNS is not None:
        return
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    path = os.path.join(data_dir, "v8_jsruns.json")
    try:
        with open(path, "r") as f:
            _JSRUNS = json.load(f)
    except Exception:
        _JSRUNS = []


def _get_jsruntime_name(idx):
    """Get the runtime function name for a context index."""
    _load_jsruns()
    if idx < len(_JSRUNS):
        entry = _JSRUNS[idx]
        if isinstance(entry, dict):
            return entry.get("Name", "")
    return ""


# Map from jsruns names -> JS static function (receiver is ignored)
_JSRUNTIME_STATIC = {
    "math_pow": "Math.pow",
    "math_floor": "Math.floor",
    "object_create": "Object.create",
    "object_define_property": "Object.defineProperty",
    "object_define_properties": "Object.defineProperties",
    "object_freeze": "Object.freeze",
    "object_get_prototype_of": "Object.getPrototypeOf",
    "object_is_extensible": "Object.isExtensible",
    "object_is_frozen": "Object.isFrozen",
    "object_is_sealed": "Object.isSealed",
    "object_keys": "Object.keys",
    "reflect_apply": "Reflect.apply",
    "reflect_construct": "Reflect.construct",
    "reflect_define_property": "Reflect.defineProperty",
    "reflect_delete_property": "Reflect.deleteProperty",
    "global_eval_fun": "eval",
    "spread_arguments": "...args",
    "spread_iterable": "...iterable",
}

# Map from jsruns names -> JS method name (receiver is first arg)
_JSRUNTIME_METHOD = {
    "array_pop": "pop",
    "array_push": "push",
    "array_shift": "shift",
    "array_unshift": "unshift",
    "array_splice": "splice",
    "array_slice": "slice",
    "array_concat": "concat",
    "map_get": "get",
    "map_set": "set",
    "map_has": "has",
    "map_delete": "delete",
    "set_add": "add",
    "set_delete": "delete",
    "set_has": "has",
    "promise_then": "then",
    "promise_catch": "catch",
    "promise_resolve": "resolve",
}


def _parse_reg_range_args(range_str, get_reg):
    """Parse a register range string into arg values.

    Handles two formats:
      - V8 6.2 binary: 'r0-_context(3)' — prefix, start, count in parens
      - V8 12.4 text:  'r1-r4'          — prefix, start-end registers
    Returns list of symbolic values for each register in the range.
    """
    range_str = range_str.rstrip(",")
    m = re.match(r'([ar])(\d+)', range_str)
    if not m:
        return []
    prefix = m.group(1)
    start_idx = int(m.group(2))

    # Try V8 12.4 dash format: r1-r4
    dm = re.match(r'[ar]\d+-([ar])(\d+)$', range_str)
    if dm:
        end_idx = int(dm.group(2))
        count = end_idx - start_idx + 1
        return [get_reg("%s%d" % (prefix, start_idx + i)) for i in range(count)]

    # Try V8 6.2 count format: r0(4)
    cm = re.search(r'\((\d+)\)', range_str)
    if not cm:
        return [get_reg("%s%d" % (prefix, start_idx))]
    count = int(cm.group(1))

    return [get_reg("%s%d" % (prefix, start_idx + i)) for i in range(count)]


# --- Helpers ---

def _reg_to_name(reg_str, params, stack_locals, stack_first_slot):
    """Convert register name (a0, r0, etc.) to variable name if available.

    Handles V8 special registers:
      <this>    → this (JavaScript receiver)
      <closure> → internal (function closure reference)
      <context> → internal (execution context)
    """
    # V8 special registers (angle-bracket names from --print-bytecode)
    if reg_str == "<this>":
        return "this"
    if reg_str in ("<closure>", "<context>"):
        return reg_str  # Keep as-is; these are internal

    if reg_str.startswith("a") and reg_str[1:].isdigit():
        idx = int(reg_str[1:])
        # V8 stores params in reverse order: a0=last param, a(N-1)=first param
        rev_idx = len(params) - 1 - idx
        if 0 <= rev_idx < len(params):
            return params[rev_idx]
    elif reg_str.startswith("r") and reg_str[1:].isdigit():
        idx = int(reg_str[1:])
        slot = idx - stack_first_slot
        if 0 <= slot < len(stack_locals) and stack_locals[slot]:
            name = stack_locals[slot]
            if name and name != "empty_string":
                return name.replace(".", "_").replace(" ", "_")
    return reg_str


def _cp_value_str(idx, constant_pool):
    """Get string representation of a constant pool entry."""
    if constant_pool is None or idx >= len(constant_pool.items):
        return "cp[%d]" % idx
    item = constant_pool.items[idx]
    if isinstance(item, str):
        if item.startswith("HeapNumber:"):
            return item[len("HeapNumber:"):]
        if item.startswith("ArrayBoilerplate:"):
            return item[len("ArrayBoilerplate:"):]
        if item.startswith("ObjBoilerplate:"):
            return item[len("ObjBoilerplate:"):]
        return '"%s"' % item.replace('"', '\\"')
    elif isinstance(item, float):
        return repr(item)
    elif isinstance(item, int):
        return str(item)
    elif isinstance(item, RootObject):
        if item.name == "empty_string":
            return '""'
        # Root objects with type 'str' are interned string constants
        if getattr(item, "type", None) == "str":
            return '"%s"' % item.name.replace('"', '\\"')
        return item.name
    elif hasattr(item, "name"):
        return str(item.name)
    elif hasattr(item, "type_name"):
        if "closure" in str(getattr(item, "name", "")):
            return str(item.name)
        return str(item.type_name)
    return "cp[%d]" % idx


# --- Main reconstructor ---

def reconstruct_js(sfi):
    """Reconstruct approximate JavaScript from a SharedFunctionInfo.

    Returns a string of pseudo-JavaScript code.
    """
    if sfi.bytecode is None:
        return "// No bytecode available for %s\n" % sfi.name

    bc = sfi.bytecode
    cp = bc.constant_pool
    ht = bc.handler_table

    # Get parameter and local names from scope
    params = []
    stack_locals = []
    stack_first_slot = 0
    context_locals = []

    if sfi.scope_info:
        params = list(sfi.scope_info.params)
        stack_locals = list(sfi.scope_info.stack_locals)
        stack_first_slot = sfi.scope_info.stack_locals_first_slot
        context_locals = list(sfi.scope_info.context_locals)

    # Disassemble
    instructions = disassemble_bytecode(bc.bytecode, cp, ht)

    # Build offset -> instruction index map for jump resolution
    offset_to_idx = {}
    for i, (offset, mnemonic, operands, raw, comment) in enumerate(instructions):
        offset_to_idx[offset] = i

    # Collect jump targets to mark as labels
    jump_targets = set()
    for offset, mnemonic, operands_str, raw, comment in instructions:
        if "-> @" in comment:
            target = int(comment.split("-> @")[1][:4], 16)
            jump_targets.add(target)

    # State machine: track accumulator and registers as symbolic expressions
    acc = "undefined"
    acc_prec = _P_ATOM
    regs = {}

    def rname(r):
        return _reg_to_name(r, params, stack_locals, stack_first_slot)

    def get_reg(r):
        name = rname(r)
        return regs.get(name, name)

    def set_reg(r, val):
        name = rname(r)
        regs[name] = val
        return name

    lines = []
    indent = "    "

    # Handler table: build try/catch ranges
    try_starts = set()
    try_ends = set()
    handler_offsets = set()
    if ht:
        for entry in ht.entries:
            try_starts.add(entry.start)
            try_ends.add(entry.end)
            handler_offsets.add(entry.handler_offset)

    for inst_idx, (offset, mnemonic, operands_str, raw_bytes, comment) in enumerate(instructions):
        # Strip Wide/ExtraWide prefix for matching
        base = mnemonic.split(".")[-1] if "." in mnemonic else mnemonic

        # Handle Star0-Star15 short-form opcodes (V8 12.4+)
        if base.startswith("Star") and len(base) > 4 and base[4:].isdigit():
            reg_num = int(base[4:])
            reg = "r%d" % reg_num
            name = rname(reg)
            is_raw = re.match(r'^[ar]\d+$', name)
            if is_raw and acc_prec < _P_ATOM:
                set_reg(reg, "(%s)" % acc)
            else:
                set_reg(reg, acc)
            if not is_raw:
                lines.append(indent + "%s = %s;" % (name, acc))
                regs[name] = name
            acc = name
            acc_prec = _P_ATOM
            continue

        # Apply V8 12.4 opcode aliases (renamed opcodes)
        base = _OPCODE_ALIASES.get(base, base)

        # Parse operands from raw instruction
        ops = _parse_operands(instructions[inst_idx])

        # Add labels for jump targets
        if offset in jump_targets:
            lines.append("")

        # Try/catch markers
        if offset in try_starts:
            lines.append(indent + "try {")
            indent = "        "
        if offset in try_ends:
            indent = "    "
            lines.append(indent + "} catch (e) {")
            indent = "        "
        if offset in handler_offsets:
            indent = "    "
            lines.append(indent + "}")

        # Skip StackCheck -- internal runtime overhead
        if base == "StackCheck":
            continue

        # === CONSTANT LOADING ===
        if base == "LdaZero":
            acc = "0"
            acc_prec = _P_ATOM
        elif base == "LdaSmi":
            val = _get_imm(ops)
            acc = str(val)
            acc_prec = _P_ATOM
        elif base == "LdaUndefined":
            acc = "undefined"
            acc_prec = _P_ATOM
        elif base == "LdaNull":
            acc = "null"
            acc_prec = _P_ATOM
        elif base == "LdaTheHole":
            acc = "undefined /* TheHole */"
            acc_prec = _P_ATOM
        elif base == "LdaTrue":
            acc = "true"
            acc_prec = _P_ATOM
        elif base == "LdaFalse":
            acc = "false"
            acc_prec = _P_ATOM
        elif base == "LdaConstant":
            idx = _get_idx(ops)
            acc = _cp_value_str(idx, cp)
            acc_prec = _P_ATOM

        # === REGISTER OPS ===
        elif base == "Ldar":
            reg = _get_reg(ops)
            acc = get_reg(reg)
            acc_prec = _P_ATOM
        elif base == "Star":
            reg = _get_reg(ops)
            name = rname(reg)
            is_raw = re.match(r'^[ar]\d+$', name)
            # For raw registers, wrap sub-expressions to preserve precedence
            if is_raw and acc_prec < _P_ATOM:
                set_reg(reg, "(%s)" % acc)
            else:
                set_reg(reg, acc)
            if not is_raw:
                lines.append(indent + "%s = %s;" % (name, acc))
                regs[name] = name  # Reset so subsequent reads use the name
            acc = name
            acc_prec = _P_ATOM
        elif base == "Mov":
            src_r, dst_r = _get_two_regs(ops)
            val = get_reg(src_r)
            name = set_reg(dst_r, val)
            if not re.match(r'^[ar]\d+$', name):
                lines.append(indent + "%s = %s;" % (name, val))
                regs[name] = name  # Reset so subsequent reads use the name

        # === GLOBAL ACCESS ===
        elif base in ("LdaGlobal", "LdaGlobalInsideTypeof"):
            idx = _get_idx(ops)
            acc = _cp_value_str(idx, cp).strip('"')
            acc_prec = _P_ATOM
        elif base in ("StaGlobalSloppy", "StaGlobalStrict"):
            idx = _get_idx(ops)
            gname = _cp_value_str(idx, cp).strip('"')
            lines.append(indent + "%s = %s;" % (gname, acc))

        # === CONTEXT SLOTS ===
        elif base in ("LdaContextSlot", "LdaImmutableContextSlot"):
            idx = _get_idx(ops)
            if idx < len(context_locals) and context_locals[idx]:
                acc = context_locals[idx]
            else:
                acc = "ctx[%d]" % idx
            acc_prec = _P_ATOM
        elif base in ("LdaCurrentContextSlot", "LdaImmutableCurrentContextSlot"):
            idx = _get_idx(ops)
            if idx < len(context_locals) and context_locals[idx]:
                acc = context_locals[idx]
            else:
                acc = "ctx[%d]" % idx
            acc_prec = _P_ATOM
        elif base == "StaContextSlot":
            idx = _get_idx(ops)
            if idx < len(context_locals) and context_locals[idx]:
                lines.append(indent + "%s = %s;" % (context_locals[idx], acc))
            else:
                lines.append(indent + "ctx[%d] = %s;" % (idx, acc))
        elif base == "StaCurrentContextSlot":
            idx = _get_idx(ops)
            if idx < len(context_locals) and context_locals[idx]:
                lines.append(indent + "%s = %s;" % (context_locals[idx], acc))
            else:
                lines.append(indent + "ctx[%d] = %s;" % (idx, acc))
        # V8 12.4 script context variants
        elif base in ("StaScriptContextSlot", "StaCurrentScriptContextSlot"):
            idx = _get_idx(ops)
            if idx < len(context_locals) and context_locals[idx]:
                lines.append(indent + "%s = %s;" % (context_locals[idx], acc))
            else:
                lines.append(indent + "ctx[%d] = %s;" % (idx, acc))

        # === ARITHMETIC (register + acc) ===
        elif base == "Add":
            reg = _get_reg(ops)
            acc = "%s + %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_ADD, '+'))
            acc_prec = _P_ADD
        elif base == "Sub":
            reg = _get_reg(ops)
            acc = "%s - %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_ADD, '-'))
            acc_prec = _P_ADD
        elif base == "Mul":
            reg = _get_reg(ops)
            acc = "%s * %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_MUL, '*'))
            acc_prec = _P_MUL
        elif base == "Div":
            reg = _get_reg(ops)
            acc = "%s / %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_MUL, '/'))
            acc_prec = _P_MUL
        elif base == "Mod":
            reg = _get_reg(ops)
            acc = "%s %% %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_MUL, '%'))
            acc_prec = _P_MUL
        elif base == "Exp":
            reg = _get_reg(ops)
            acc = "%s ** %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_EXP, '**'))
            acc_prec = _P_EXP

        # === ARITHMETIC (acc OP Smi) ===
        elif base == "AddSmi":
            val = _get_imm(ops)
            acc = "%s + %s" % (_wrap_left(acc, acc_prec, _P_ADD), val)
            acc_prec = _P_ADD
        elif base == "SubSmi":
            val = _get_imm(ops)
            acc = "%s - %s" % (_wrap_left(acc, acc_prec, _P_ADD), val)
            acc_prec = _P_ADD
        elif base == "MulSmi":
            val = _get_imm(ops)
            acc = "%s * %s" % (_wrap_left(acc, acc_prec, _P_MUL), val)
            acc_prec = _P_MUL
        elif base == "DivSmi":
            val = _get_imm(ops)
            acc = "%s / %s" % (_wrap_left(acc, acc_prec, _P_MUL), val)
            acc_prec = _P_MUL
        elif base == "ModSmi":
            val = _get_imm(ops)
            acc = "%s %% %s" % (_wrap_left(acc, acc_prec, _P_MUL), val)
            acc_prec = _P_MUL
        elif base == "ExpSmi":
            val = _get_imm(ops)
            acc = "%s ** %s" % (_wrap_left(acc, acc_prec, _P_EXP), val)
            acc_prec = _P_EXP

        # === BITWISE (register + acc) ===
        elif base == "BitwiseOr":
            reg = _get_reg(ops)
            acc = "%s | %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_OR, '|'))
            acc_prec = _P_OR
        elif base == "BitwiseXor":
            reg = _get_reg(ops)
            acc = "%s ^ %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_XOR, '^'))
            acc_prec = _P_XOR
        elif base == "BitwiseAnd":
            reg = _get_reg(ops)
            acc = "%s & %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_AND, '&'))
            acc_prec = _P_AND
        elif base == "ShiftLeft":
            reg = _get_reg(ops)
            acc = "%s << %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_SHIFT, '<<'))
            acc_prec = _P_SHIFT
        elif base == "ShiftRight":
            reg = _get_reg(ops)
            acc = "%s >> %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_SHIFT, '>>'))
            acc_prec = _P_SHIFT
        elif base == "ShiftRightLogical":
            reg = _get_reg(ops)
            acc = "%s >>> %s" % (get_reg(reg), _wrap_right(acc, acc_prec, _P_SHIFT, '>>>'))
            acc_prec = _P_SHIFT

        # === BITWISE (acc OP Smi) ===
        elif base == "BitwiseOrSmi":
            val = _get_imm(ops)
            acc = "%s | %s" % (_wrap_left(acc, acc_prec, _P_OR), val)
            acc_prec = _P_OR
        elif base == "BitwiseXorSmi":
            val = _get_imm(ops)
            acc = "%s ^ %s" % (_wrap_left(acc, acc_prec, _P_XOR), val)
            acc_prec = _P_XOR
        elif base == "BitwiseAndSmi":
            val = _get_imm(ops)
            acc = "%s & %s" % (_wrap_left(acc, acc_prec, _P_AND), val)
            acc_prec = _P_AND
        elif base == "ShiftLeftSmi":
            val = _get_imm(ops)
            acc = "%s << %s" % (_wrap_left(acc, acc_prec, _P_SHIFT), val)
            acc_prec = _P_SHIFT
        elif base == "ShiftRightSmi":
            val = _get_imm(ops)
            acc = "%s >> %s" % (_wrap_left(acc, acc_prec, _P_SHIFT), val)
            acc_prec = _P_SHIFT
        elif base == "ShiftRightLogicalSmi":
            val = _get_imm(ops)
            acc = "%s >>> %s" % (_wrap_left(acc, acc_prec, _P_SHIFT), val)
            acc_prec = _P_SHIFT

        # === UNARY ===
        elif base == "Inc":
            acc = "%s + 1" % _wrap_left(acc, acc_prec, _P_ADD)
            acc_prec = _P_ADD
        elif base == "Dec":
            acc = "%s - 1" % _wrap_left(acc, acc_prec, _P_ADD)
            acc_prec = _P_ADD
        elif base == "ToBooleanLogicalNot":
            if acc_prec < _P_ATOM:
                acc = "!(%s)" % acc
            else:
                acc = "!%s" % acc
            acc_prec = _P_ATOM
        elif base == "LogicalNot":
            if acc_prec < _P_ATOM:
                acc = "!(%s)" % acc
            else:
                acc = "!%s" % acc
            acc_prec = _P_ATOM
        elif base == "TypeOf":
            acc = "typeof %s" % acc
            acc_prec = _P_ATOM
        elif base == "Negate":
            acc = "-%s" % _wrap_left(acc, acc_prec, _P_ATOM)
            acc_prec = _P_ATOM
        elif base == "BitwiseNot":
            acc = "~%s" % _wrap_left(acc, acc_prec, _P_ATOM)
            acc_prec = _P_ATOM
        elif base in ("DeletePropertyStrict", "DeletePropertySloppy"):
            reg = _get_reg(ops)
            key = acc
            if key.startswith('"') and key.endswith('"') and _is_valid_identifier(key.strip('"')):
                acc = "delete %s.%s" % (get_reg(reg), key.strip('"'))
            else:
                acc = "delete %s[%s]" % (get_reg(reg), key)
            acc_prec = _P_ATOM
            lines.append(indent + "%s;" % acc)

        # === COMPARISON ===
        elif base == "TestEqual":
            reg = _get_reg(ops)
            acc = "%s == %s" % (get_reg(reg), acc)
            acc_prec = _P_EQ
        elif base in ("TestEqualStrict", "TestEqualStrictNoFeedback"):
            reg = _get_reg(ops)
            acc = "%s === %s" % (get_reg(reg), acc)
            acc_prec = _P_EQ
        elif base == "TestLessThan":
            reg = _get_reg(ops)
            acc = "%s < %s" % (get_reg(reg), acc)
            acc_prec = _P_REL
        elif base == "TestGreaterThan":
            reg = _get_reg(ops)
            acc = "%s > %s" % (get_reg(reg), acc)
            acc_prec = _P_REL
        elif base == "TestLessThanOrEqual":
            reg = _get_reg(ops)
            acc = "%s <= %s" % (get_reg(reg), acc)
            acc_prec = _P_REL
        elif base == "TestGreaterThanOrEqual":
            reg = _get_reg(ops)
            acc = "%s >= %s" % (get_reg(reg), acc)
            acc_prec = _P_REL
        elif base == "TestInstanceOf":
            reg = _get_reg(ops)
            acc = "%s instanceof %s" % (get_reg(reg), acc)
            acc_prec = _P_REL
        elif base == "TestIn":
            reg = _get_reg(ops)
            acc = "%s in %s" % (get_reg(reg), acc)
            acc_prec = _P_REL
        elif base == "TestUndetectable":
            acc = "%s == null" % acc
            acc_prec = _P_EQ
        elif base == "TestNull":
            acc = "%s === null" % acc
            acc_prec = _P_EQ
        elif base == "TestUndefined":
            acc = "%s === undefined" % acc
            acc_prec = _P_EQ
        elif base == "TestTypeOf":
            flag = _get_flag8(ops)
            if flag < len(TYPEOF_LITERALS):
                acc = 'typeof %s === "%s"' % (acc, TYPEOF_LITERALS[flag])
            else:
                acc = "typeof %s === ?" % acc
            acc_prec = _P_EQ

        # === PROPERTY ACCESS ===
        elif base == "LdaNamedProperty":
            reg = _get_reg(ops)
            idx = _get_idx(ops)
            prop = _cp_value_str(idx, cp).strip('"')
            obj_name = get_reg(reg)
            if _is_valid_identifier(prop):
                acc = "%s.%s" % (obj_name, prop)
            else:
                acc = '%s["%s"]' % (obj_name, prop)
            acc_prec = _P_ATOM
        elif base == "LdaKeyedProperty":
            reg = _get_reg(ops)
            acc = "%s[%s]" % (get_reg(reg), acc)
            acc_prec = _P_ATOM
        elif base in ("StaNamedPropertySloppy", "StaNamedPropertyStrict", "StaNamedOwnProperty"):
            reg = _get_reg(ops)
            idx = _get_idx(ops)
            prop = _cp_value_str(idx, cp).strip('"')
            obj_name = get_reg(reg)
            if _is_valid_identifier(prop):
                lines.append(indent + "%s.%s = %s;" % (obj_name, prop, acc))
            else:
                lines.append(indent + '%s["%s"] = %s;' % (obj_name, prop, acc))
        elif base in ("StaKeyedPropertySloppy", "StaKeyedPropertyStrict"):
            reg = _get_reg(ops)
            key_reg = _get_second_reg(ops)
            lines.append(indent + "%s[%s] = %s;" % (get_reg(reg), get_reg(key_reg), acc))

        # === FUNCTION CALLS ===
        elif base in ("CallProperty0", "CallUndefinedReceiver0"):
            reg = _get_reg(ops)
            acc = "%s()" % get_reg(reg)
            acc_prec = _P_ATOM
        elif base == "CallProperty1":
            # callable receiver arg1 [feedback]
            parts = operands_str.split()
            callable_r = parts[0] if parts else "?"
            arg1_r = parts[2] if len(parts) > 2 else "?"
            acc = "%s(%s)" % (get_reg(callable_r), get_reg(arg1_r))
            acc_prec = _P_ATOM
        elif base == "CallProperty2":
            # callable receiver arg1 arg2 [feedback]
            parts = operands_str.split()
            callable_r = parts[0] if parts else "?"
            arg1_r = parts[2] if len(parts) > 2 else "?"
            arg2_r = parts[3] if len(parts) > 3 else "?"
            acc = "%s(%s, %s)" % (get_reg(callable_r), get_reg(arg1_r), get_reg(arg2_r))
            acc_prec = _P_ATOM
        elif base == "CallUndefinedReceiver1":
            parts = operands_str.split()
            callable_r = parts[0] if parts else "?"
            arg1_r = parts[1] if len(parts) > 1 else "?"
            acc = "%s(%s)" % (get_reg(callable_r), get_reg(arg1_r))
            acc_prec = _P_ATOM
        elif base == "CallUndefinedReceiver2":
            parts = operands_str.split()
            callable_r = parts[0] if parts else "?"
            arg1_r = parts[1] if len(parts) > 1 else "?"
            arg2_r = parts[2] if len(parts) > 2 else "?"
            acc = "%s(%s, %s)" % (get_reg(callable_r), get_reg(arg1_r), get_reg(arg2_r))
            acc_prec = _P_ATOM
        elif base in ("CallProperty", "CallAnyReceiver", "CallWithSpread"):
            # callable reg_range [feedback] — first in range is receiver
            parts = operands_str.split()
            callable_r = parts[0] if parts else "?"
            range_str = parts[1] if len(parts) > 1 else ""
            range_args = _parse_reg_range_args(range_str, get_reg)
            call_args = range_args[1:] if len(range_args) > 1 else []
            acc = "%s(%s)" % (get_reg(callable_r), ", ".join(call_args))
            acc_prec = _P_ATOM
        elif base == "CallUndefinedReceiver":
            # callable reg_range [feedback] — receiver is implicit undefined, all range regs are args
            parts = operands_str.split()
            callable_r = parts[0] if parts else "?"
            range_str = parts[1] if len(parts) > 1 else ""
            range_args = _parse_reg_range_args(range_str, get_reg)
            acc = "%s(%s)" % (get_reg(callable_r), ", ".join(range_args))
            acc_prec = _P_ATOM
        elif base == "CallRuntime":
            acc = "/* CallRuntime(%s) */" % operands_str
            acc_prec = _P_ATOM

        elif base == "CallJSRuntime":
            idx = _get_idx(ops)
            # Parse register range (second operand)
            range_str = ops[1] if len(ops) > 1 else ""
            range_args = _parse_reg_range_args(range_str, get_reg)
            rt_name = _get_jsruntime_name(idx)
            if rt_name:
                js_static = _JSRUNTIME_STATIC.get(rt_name)
                js_method = _JSRUNTIME_METHOD.get(rt_name)
                if js_static:
                    # Static function: skip receiver (first register)
                    arg_strs = range_args[1:] if len(range_args) > 1 else []
                    acc = "%s(%s)" % (js_static, ", ".join(arg_strs))
                elif js_method:
                    # Method call: receiver.method(args)
                    if range_args:
                        receiver = range_args[0]
                        arg_strs = range_args[1:] if len(range_args) > 1 else []
                        acc = "%s.%s(%s)" % (receiver, js_method, ", ".join(arg_strs))
                    else:
                        acc = "%s()" % js_method
                else:
                    # Unknown runtime: show the name
                    arg_strs = range_args[1:] if len(range_args) > 1 else range_args
                    acc = "%s(%s)" % (rt_name, ", ".join(arg_strs))
            else:
                acc = "/* JSRuntime[%d](...) */" % idx
            acc_prec = _P_ATOM

        elif base == "InvokeIntrinsic":
            acc = "/* InvokeIntrinsic(%s) */" % operands_str
            acc_prec = _P_ATOM
        elif base == "ConstructForwardAllArgs":
            parts = operands_str.split()
            ctor_r = parts[0] if parts else "?"
            acc = "new %s(...args)" % get_reg(ctor_r)
            acc_prec = _P_ATOM
        elif base in ("Construct", "ConstructWithSpread"):
            parts = operands_str.split()
            ctor_r = parts[0] if parts else "?"
            range_str = parts[1] if len(parts) > 1 else ""
            range_args = _parse_reg_range_args(range_str, get_reg)
            # Last register in range is new.target, skip it
            call_args = range_args[:-1] if len(range_args) > 1 else range_args
            acc = "new %s(%s)" % (get_reg(ctor_r), ", ".join(call_args))
            acc_prec = _P_ATOM

        # === OBJECT CREATION ===
        elif base == "CreateClosure":
            idx = _get_idx(ops)
            closure_name = _cp_value_str(idx, cp)
            acc = closure_name
            acc_prec = _P_ATOM
        elif base == "CreateArrayLiteral":
            arr_str = None
            if cp is not None:
                bp_idx = _get_idx(ops)
                raw = _cp_value_str(bp_idx, cp)
                if raw.startswith("["):
                    arr_str = raw
            acc = arr_str if arr_str else "[]"
            acc_prec = _P_ATOM
        elif base == "CreateEmptyArrayLiteral":
            acc = "[]"
            acc_prec = _P_ATOM
        elif base in ("CreateObjectLiteral", "CreateEmptyObjectLiteral"):
            acc = "{}"
            acc_prec = _P_ATOM
        elif base == "CloneObject":
            reg = _get_reg(ops)
            acc = "{...%s}" % get_reg(reg)
            acc_prec = _P_ATOM
        elif base == "CreateArrayFromIterable":
            acc = "[...%s]" % acc
            acc_prec = _P_ATOM
        elif base == "GetTemplateObject":
            acc = "/* template object */"
            acc_prec = _P_ATOM
        elif base == "CreateRegExpLiteral":
            idx = _get_idx(ops)
            acc = "/%s/" % _cp_value_str(idx, cp).strip('"')
            acc_prec = _P_ATOM

        # === CONTEXT CREATION ===
        elif base == "CreateFunctionContext":
            pass  # Internal, skip
        elif base == "CreateBlockContext":
            pass  # Internal, skip
        elif base == "CreateCatchContext":
            pass  # Internal, skip
        elif base == "PushContext":
            pass  # Internal, skip
        elif base == "PopContext":
            pass  # Internal, skip

        # === CONTROL FLOW ===
        elif base == "Return":
            lines.append(indent + "return %s;" % acc)

        elif base == "JumpLoop":
            # Backward jump = loop
            if "-> @" in comment:
                target = int(comment.split("-> @")[1][:4], 16)
                lines.append(indent + "/* loop back to @%04X */" % target)
            else:
                lines.append(indent + "/* loop */")

        elif base == "Jump":
            if "-> @" in comment:
                target = int(comment.split("-> @")[1][:4], 16)
                lines.append(indent + "/* goto @%04X */" % target)

        elif base.startswith("JumpIf"):
            cond = _jump_condition(base, acc)
            if "-> @" in comment:
                target = int(comment.split("-> @")[1][:4], 16)
                lines.append(indent + "if (%s) { /* goto @%04X */ }" % (cond, target))
            else:
                lines.append(indent + "if (%s) { ... }" % cond)

        # === THROW / SPECIAL ===
        elif base == "Throw":
            lines.append(indent + "throw %s;" % acc)
        elif base == "ReThrow":
            lines.append(indent + "throw %s; /* rethrow */" % acc)
        elif base in ("ThrowReferenceErrorIfHole",):
            idx = _get_idx(ops)
            lines.append(indent + "/* ThrowReferenceErrorIfHole %s */" % _cp_value_str(idx, cp))

        # === FOR-IN ===
        elif base == "ForInPrepare":
            reg = _get_reg(ops)
            lines.append(indent + "/* for (... in %s) prepare */" % get_reg(reg))
        elif base == "ForInNext":
            reg = _get_reg(ops)
            acc = "/* ForInNext(%s) */" % get_reg(reg)
            acc_prec = _P_ATOM
        elif base == "ForInStep":
            reg = _get_reg(ops)
            acc = "%s + 1" % get_reg(reg)
            acc_prec = _P_ADD
        elif base == "ForInContinue":
            reg = _get_reg(ops)
            second = _get_second_reg(ops)
            acc = "%s < %s" % (get_reg(reg), get_reg(second))
            acc_prec = _P_REL

        # === GENERATORS ===
        elif base in ("SuspendGenerator", "ResumeGenerator",
                       "RestoreGeneratorState", "RestoreGeneratorRegisters",
                       "SwitchOnGeneratorState"):
            lines.append(indent + "/* %s %s */" % (base, operands_str))

        # === LOOKUP ===
        elif base.startswith("LdaLookup"):
            idx = _get_idx(ops)
            acc = _cp_value_str(idx, cp).strip('"')
            acc_prec = _P_ATOM
        elif base == "StaLookupSlot":
            idx = _get_idx(ops)
            name = _cp_value_str(idx, cp).strip('"')
            lines.append(indent + "%s = %s;" % (name, acc))

        # === MODULE ===
        elif base == "LdaModuleVariable":
            acc = "/* module_var */"
            acc_prec = _P_ATOM
        elif base == "StaModuleVariable":
            lines.append(indent + "/* StaModuleVariable = %s */" % acc)

        # === MISC ===
        elif base in ("Nop", "Illegal", "DebugBreakWide", "DebugBreakExtraWide",
                       "SetPendingMessage", "Wide", "ExtraWide"):
            pass  # Skip
        elif base.startswith("DebugBreak") or base == "Debugger":
            lines.append(indent + "debugger;")
        elif base == "SwitchOnSmiNoFeedback":
            lines.append(indent + "/* switch (%s) { ... } */" % acc)
        elif base == "ToNumber":
            # Saves acc to destination register (used in n++/n-- patterns)
            reg = _get_reg(ops)
            if reg != "?":
                set_reg(reg, acc)
        elif base in ("ToName", "ToObject", "ToBoolean", "ToNumeric", "ToString"):
            pass  # Implicit coercion, skip
        elif base in ("GetSuperConstructor",):
            reg = _get_reg(ops)
            lines.append(indent + "%s = super.constructor;" % rname(reg))
        elif base in ("CreateMappedArguments", "CreateUnmappedArguments"):
            acc = "arguments"
            acc_prec = _P_ATOM
        elif base == "CreateRestParameter":
            acc = "[...rest]"
            acc_prec = _P_ATOM
        elif base in ("ThrowSuperNotCalledIfHole", "ThrowSuperAlreadyCalledIfNotHole",
                       "ThrowIfNotSuperConstructor",
                       "FindNonDefaultConstructorOrConstruct",
                       "IncBlockCounter", "CollectTypeProfile",
                       "StaDataPropertyInLiteral", "StaInArrayLiteral",
                       "GetIterator", "Abort"):
            pass  # Internal, skip
        elif base == "CreateWithContext":
            pass  # with() context, skip
        elif base == "CreateEvalContext":
            pass  # eval context, skip
        else:
            # Unknown opcode -- emit as comment
            lines.append(indent + "/* %s %s */" % (mnemonic, operands_str))

        # Auto-emit call expressions as statements when the result is not
        # consumed by the next instruction.
        if base in _CALL_OPCODES:
            next_base = ""
            if inst_idx + 1 < len(instructions):
                next_mn = instructions[inst_idx + 1][1]
                next_base = next_mn.split(".")[-1] if "." in next_mn else next_mn
            acc_consumed = (
                next_base in ("Star", "Return",
                              "LogicalNot", "ToBooleanLogicalNot", "TypeOf",
                              "ToNumber", "ToName", "ToObject",
                              "ToBoolean", "ToNumeric", "ToString",
                              "Throw", "ReThrow",
                              # Binary/arithmetic ops that consume acc
                              "Add", "Sub", "Mul", "Div", "Mod", "Exp",
                              "AddSmi", "SubSmi", "MulSmi", "DivSmi",
                              "ModSmi", "ExpSmi",
                              "BitwiseOr", "BitwiseXor", "BitwiseAnd",
                              "BitwiseOrSmi", "BitwiseXorSmi", "BitwiseAndSmi",
                              "ShiftLeft", "ShiftRight", "ShiftRightLogical",
                              "ShiftLeftSmi", "ShiftRightSmi",
                              # Unary ops that consume acc
                              "Inc", "Dec", "Negate", "BitwiseNot",
                              # Construct ops
                              "Construct", "ConstructWithSpread")
                or next_base.startswith("JumpIf")
                or next_base.startswith("Sta")
                or next_base.startswith("Star")  # Star0-Star15
                or next_base.startswith("Test")
            )
            if not acc_consumed:
                lines.append(indent + "%s;" % acc)

    return "\n".join(lines)


# === Shared helpers ===

def _jump_condition(mnemonic, acc):
    """Convert a JumpIf* mnemonic to a JS condition expression.

    Returns the condition under which the JUMP is taken.
    """
    base = mnemonic.split(".")[-1] if "." in mnemonic else mnemonic

    if base == "JumpIfTrue":
        return acc
    elif base == "JumpIfFalse":
        return "!(%s)" % acc
    elif base == "JumpIfToBooleanTrue":
        return "!!(%s)" % acc
    elif base == "JumpIfToBooleanFalse":
        return "!(%s)"  % acc
    elif base == "JumpIfNull":
        return "%s === null" % acc
    elif base == "JumpIfNotNull":
        return "%s !== null" % acc
    elif base == "JumpIfUndefined":
        return "%s === undefined" % acc
    elif base == "JumpIfNotUndefined":
        return "%s !== undefined" % acc
    elif base == "JumpIfUndefinedOrNull":
        return "%s == null" % acc
    elif base == "JumpIfJSReceiver":
        return "typeof %s === 'object'" % acc
    # Constant variants
    elif "Constant" in base:
        if "True" in base:
            return acc
        elif "False" in base:
            return "!(%s)" % acc
        elif "Null" in base and "Not" in base:
            return "%s !== null" % acc
        elif "Null" in base:
            return "%s === null" % acc
        elif "Undefined" in base and "Not" in base:
            return "%s !== undefined" % acc
        elif "Undefined" in base:
            return "%s === undefined" % acc
        elif "UndefinedOrNull" in base:
            return "%s == null" % acc
        elif "JSReceiver" in base:
            return "typeof %s === 'object'" % acc
        elif "ToBooleanTrue" in base:
            return "!!(%s)" % acc
        elif "ToBooleanFalse" in base:
            return "!(%s)" % acc
    return acc


def _is_valid_identifier(s):
    """Check if a string is a valid JS identifier."""
    if not s or not (s[0].isalpha() or s[0] == '_' or s[0] == '$'):
        return False
    return all(c.isalnum() or c in ('_', '$') for c in s)


# === Operand extraction helpers ===

def _parse_operands(inst_tuple):
    """Return the operands_str split into parts."""
    return inst_tuple[2].split() if inst_tuple[2] else []


def _clean_op(val):
    """Strip trailing commas and whitespace from an operand token."""
    return val.rstrip(",").strip()


def _get_reg(ops):
    """Get first register operand."""
    return _clean_op(ops[0]) if ops else "?"


def _get_second_reg(ops):
    """Get second register operand."""
    return _clean_op(ops[1]) if len(ops) > 1 else "?"


def _get_two_regs(ops):
    """Get two register operands."""
    src = _clean_op(ops[0]) if ops else "?"
    dst = _clean_op(ops[1]) if len(ops) > 1 else "?"
    return src, dst


def _get_imm(ops):
    """Get first immediate value (strip brackets)."""
    for op in ops:
        c = _clean_op(op)
        if c.startswith("[") and c.endswith("]"):
            try:
                return int(c[1:-1])
            except ValueError:
                pass
    return 0


def _get_idx(ops):
    """Get first index value (strip brackets)."""
    for op in ops:
        c = _clean_op(op)
        if c.startswith("[") and c.endswith("]"):
            try:
                return int(c[1:-1])
            except ValueError:
                pass
    return 0
