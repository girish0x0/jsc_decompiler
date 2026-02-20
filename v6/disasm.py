"""
V8 Bytecode Disassembler — ported from v8.slaspec

Operand types:
  kReg     - register operand (maps byte to a0-a125, r123-r0)
  kImm     - signed immediate
  kIdx     - constant pool index (unsigned)
  kUImm    - unsigned immediate
  kFlag8   - flag byte
  kIntrinsicId - intrinsic ID (1 byte)
  kRuntimeId   - runtime ID (2 bytes, little-endian)
  kRegRange    - register + count (for variadic calls)
"""

import struct

# Operand type constants
kReg = "kReg"
kImm = "kImm"
kIdx = "kIdx"
kUImm = "kUImm"
kFlag8 = "kFlag8"
kIntrinsicId = "kIntrinsicId"
kRuntimeId = "kRuntimeId"
kRegRange = "kRegRange"  # register + count
kRegPair = "kRegPair"    # register pair
kRegTriple = "kRegTriple" # register triple

# Opcode table: opcode -> (mnemonic, [operand_types])
OPCODES = {
    0x00: ("Wide", []),       # Wide prefix
    0x01: ("ExtraWide", []),  # ExtraWide prefix
    0x02: ("LdaZero", []),
    0x03: ("LdaSmi", [kImm]),
    0x04: ("LdaUndefined", []),
    0x05: ("LdaNull", []),
    0x06: ("LdaTheHole", []),
    0x07: ("LdaTrue", []),
    0x08: ("LdaFalse", []),
    0x09: ("LdaConstant", [kIdx]),
    0x0a: ("LdaGlobal", [kIdx, kIdx]),
    0x0b: ("LdaGlobalInsideTypeof", [kIdx, kIdx]),
    0x0c: ("StaGlobalSloppy", [kIdx, kIdx]),
    0x0d: ("StaGlobalStrict", [kIdx, kIdx]),
    0x0e: ("PushContext", [kReg]),
    0x0f: ("PopContext", [kReg]),
    0x10: ("LdaContextSlot", [kReg, kIdx, kUImm]),
    0x11: ("LdaImmutableContextSlot", [kReg, kIdx, kUImm]),
    0x12: ("LdaCurrentContextSlot", [kIdx]),
    0x13: ("LdaImmutableCurrentContextSlot", [kIdx]),
    0x14: ("StaContextSlot", [kReg, kIdx, kUImm]),
    0x15: ("StaCurrentContextSlot", [kIdx]),
    0x16: ("LdaLookupSlot", [kIdx]),
    0x17: ("LdaLookupContextSlot", [kIdx, kIdx, kUImm]),
    0x18: ("LdaLookupGlobalSlot", [kIdx, kIdx, kUImm]),
    0x19: ("LdaLookupSlotInsideTypeof", [kIdx]),
    0x1a: ("LdaLookupContextSlotInsideTypeof", [kIdx, kIdx, kUImm]),
    0x1b: ("LdaLookupGlobalSlotInsideTypeof", [kIdx, kIdx, kUImm]),
    0x1c: ("StaLookupSlot", [kIdx, kFlag8]),
    0x1d: ("Ldar", [kReg]),
    0x1e: ("Star", [kReg]),
    0x1f: ("Mov", [kReg, kReg]),
    0x20: ("LdaNamedProperty", [kReg, kIdx, kIdx]),
    0x21: ("LdaKeyedProperty", [kReg, kIdx]),
    0x22: ("LdaModuleVariable", [kImm, kUImm]),
    0x23: ("StaModuleVariable", [kImm, kUImm]),
    0x24: ("StaNamedPropertySloppy", [kReg, kIdx, kIdx]),
    0x25: ("StaNamedPropertyStrict", [kReg, kIdx, kIdx]),
    0x26: ("StaNamedOwnProperty", [kReg, kIdx, kIdx]),
    0x27: ("StaKeyedPropertySloppy", [kReg, kReg, kIdx]),
    0x28: ("StaKeyedPropertyStrict", [kReg, kReg, kIdx]),
    0x29: ("StaDataPropertyInLiteral", [kReg, kReg, kFlag8, kIdx]),
    0x2a: ("CollectTypeProfile", [kImm]),
    0x2b: ("Add", [kReg, kIdx]),
    0x2c: ("Sub", [kReg, kIdx]),
    0x2d: ("Mul", [kReg, kIdx]),
    0x2e: ("Div", [kReg, kIdx]),
    0x2f: ("Mod", [kReg, kIdx]),
    0x30: ("BitwiseOr", [kReg, kIdx]),
    0x31: ("BitwiseXor", [kReg, kIdx]),
    0x32: ("BitwiseAnd", [kReg, kIdx]),
    0x33: ("ShiftLeft", [kReg, kIdx]),
    0x34: ("ShiftRight", [kReg, kIdx]),
    0x35: ("ShiftRightLogical", [kReg, kIdx]),
    0x36: ("AddSmi", [kImm, kIdx]),
    0x37: ("SubSmi", [kImm, kIdx]),
    0x38: ("MulSmi", [kImm, kIdx]),
    0x39: ("DivSmi", [kImm, kIdx]),
    0x3a: ("ModSmi", [kImm, kIdx]),
    0x3b: ("BitwiseOrSmi", [kImm, kIdx]),
    0x3c: ("BitwiseXorSmi", [kImm, kIdx]),
    0x3d: ("BitwiseAndSmi", [kImm, kIdx]),
    0x3e: ("ShiftLeftSmi", [kImm, kIdx]),
    0x3f: ("ShiftRightSmi", [kImm, kIdx]),
    0x40: ("ShiftRightLogicalSmi", [kImm, kIdx]),
    0x41: ("Inc", [kIdx]),
    0x42: ("Dec", [kIdx]),
    0x43: ("ToBooleanLogicalNot", []),
    0x44: ("LogicalNot", []),
    0x45: ("TypeOf", []),
    0x46: ("DeletePropertyStrict", [kReg]),
    0x47: ("DeletePropertySloppy", [kReg]),
    0x48: ("GetSuperConstructor", [kReg]),
    0x49: ("CallAnyReceiver", [kReg, kRegRange, kIdx]),
    0x4a: ("CallProperty", [kReg, kRegRange, kIdx]),
    0x4b: ("CallProperty0", [kReg, kReg, kIdx]),
    0x4c: ("CallProperty1", [kReg, kReg, kReg, kIdx]),
    0x4d: ("CallProperty2", [kReg, kReg, kReg, kReg, kIdx]),
    0x4e: ("CallUndefinedReceiver", [kReg, kRegRange, kIdx]),
    0x4f: ("CallUndefinedReceiver0", [kReg, kIdx]),
    0x50: ("CallUndefinedReceiver1", [kReg, kReg, kIdx]),
    0x51: ("CallUndefinedReceiver2", [kReg, kReg, kReg, kIdx]),
    0x52: ("CallWithSpread", [kReg, kRegRange, kIdx]),
    0x53: ("CallRuntime", [kRuntimeId, kRegRange]),
    0x54: ("CallRuntimeForPair", [kRuntimeId, kRegRange, kRegPair]),
    0x55: ("CallJSRuntime", [kIdx, kRegRange]),
    0x56: ("InvokeIntrinsic", [kIntrinsicId, kRegRange]),
    0x57: ("Construct", [kReg, kRegRange, kIdx]),
    0x58: ("ConstructWithSpread", [kReg, kRegRange, kIdx]),
    0x59: ("TestEqual", [kReg, kIdx]),
    0x5a: ("TestEqualStrict", [kReg, kIdx]),
    0x5b: ("TestLessThan", [kReg, kIdx]),
    0x5c: ("TestGreaterThan", [kReg, kIdx]),
    0x5d: ("TestLessThanOrEqual", [kReg, kIdx]),
    0x5e: ("TestGreaterThanOrEqual", [kReg, kIdx]),
    0x5f: ("TestEqualStrictNoFeedback", [kReg]),
    0x60: ("TestInstanceOf", [kReg]),
    0x61: ("TestIn", [kReg]),
    0x62: ("TestUndetectable", []),
    0x63: ("TestNull", []),
    0x64: ("TestUndefined", []),
    0x65: ("TestTypeOf", [kFlag8]),
    0x66: ("ToName", [kReg]),
    0x67: ("ToNumber", [kReg, kIdx]),
    0x68: ("ToObject", [kReg]),
    0x69: ("CreateRegExpLiteral", [kIdx, kIdx, kFlag8]),
    0x6a: ("CreateArrayLiteral", [kIdx, kIdx, kFlag8]),
    0x6b: ("CreateEmptyArrayLiteral", [kIdx]),
    0x6c: ("CreateObjectLiteral", [kIdx, kIdx, kFlag8, kReg]),
    0x6d: ("CreateEmptyObjectLiteral", []),
    0x6e: ("CreateClosure", [kIdx, kIdx, kFlag8]),
    0x6f: ("CreateBlockContext", [kIdx]),
    0x70: ("CreateCatchContext", [kReg, kIdx, kIdx]),
    0x71: ("CreateFunctionContext", [kUImm]),
    0x72: ("CreateEvalContext", [kUImm]),
    0x73: ("CreateWithContext", [kReg, kIdx]),
    0x74: ("CreateMappedArguments", []),
    0x75: ("CreateUnmappedArguments", []),
    0x76: ("CreateRestParameter", []),
    0x77: ("JumpLoop", [kUImm, kImm]),
    0x78: ("Jump", [kUImm]),
    0x79: ("JumpConstant", [kIdx]),
    0x7a: ("JumpIfNullConstant", [kIdx]),
    0x7b: ("JumpIfNotNullConstant", [kIdx]),
    0x7c: ("JumpIfUndefinedConstant", [kIdx]),
    0x7d: ("JumpIfNotUndefinedConstant", [kIdx]),
    0x7e: ("JumpIfTrueConstant", [kIdx]),
    0x7f: ("JumpIfFalseConstant", [kIdx]),
    0x80: ("JumpIfJSReceiverConstant", [kIdx]),
    0x81: ("JumpIfToBooleanTrueConstant", [kIdx]),
    0x82: ("JumpIfToBooleanFalseConstant", [kIdx]),
    0x83: ("JumpIfToBooleanTrue", [kUImm]),
    0x84: ("JumpIfToBooleanFalse", [kUImm]),
    0x85: ("JumpIfTrue", [kUImm]),
    0x86: ("JumpIfFalse", [kUImm]),
    0x87: ("JumpIfNull", [kUImm]),
    0x88: ("JumpIfNotNull", [kUImm]),
    0x89: ("JumpIfUndefined", [kUImm]),
    0x8a: ("JumpIfNotUndefined", [kUImm]),
    0x8b: ("JumpIfJSReceiver", [kUImm]),
    0x8c: ("SwitchOnSmiNoFeedback", [kIdx, kUImm, kImm]),
    0x8d: ("ForInPrepare", [kReg, kRegTriple]),
    0x8e: ("ForInContinue", [kReg, kReg]),
    0x8f: ("ForInNext", [kReg, kReg, kRegPair, kIdx]),
    0x90: ("ForInStep", [kReg]),
    0x91: ("StackCheck", []),
    0x92: ("SetPendingMessage", []),
    0x93: ("Throw", []),
    0x94: ("ReThrow", []),
    0x95: ("Return", []),
    0x96: ("ThrowReferenceErrorIfHole", [kIdx]),
    0x97: ("ThrowSuperNotCalledIfHole", []),
    0x98: ("ThrowSuperAlreadyCalledIfNotHole", []),
    0x99: ("RestoreGeneratorState", [kReg]),
    0x9a: ("SuspendGenerator", [kReg, kRegRange, kUImm]),
    0x9b: ("RestoreGeneratorRegisters", [kReg, kRegRange]),
    0x9c: ("Debugger", []),
    0x9d: ("DebugBreak0", []),
    0x9e: ("DebugBreak1", [kReg]),
    0x9f: ("DebugBreak2", [kReg, kReg]),
    0xa0: ("DebugBreak3", [kReg, kReg, kReg]),
    0xa1: ("DebugBreak4", [kReg, kReg, kReg, kReg]),
    0xa2: ("DebugBreak5", [kRuntimeId, kReg, kReg]),
    0xa3: ("DebugBreak6", [kRuntimeId, kReg, kReg, kReg]),
    0xa4: ("DebugBreakWide", []),
    0xa5: ("DebugBreakExtraWide", []),
    0xa6: ("IncBlockCounter", [kIdx]),
    0xa7: ("Illegal", []),
    0xa8: ("Nop", []),
}

# Jump instructions that go forward (inst_start + kUImm)
FORWARD_JUMPS = {
    "Jump", "JumpIfToBooleanTrue", "JumpIfToBooleanFalse",
    "JumpIfTrue", "JumpIfFalse",
    "JumpIfNull", "JumpIfNotNull",
    "JumpIfUndefined", "JumpIfNotUndefined",
    "JumpIfJSReceiver",
}

# Jump instructions that go backward (inst_start - kUImm)
BACKWARD_JUMPS = {"JumpLoop"}

# TypeOf literal names
TYPEOF_LITERALS = [
    "number", "string", "symbol", "boolean", "undefined",
    "function", "object", "other"
]

# Register mapping:
# bytes 2-127:  a0 - a125
# bytes 128-251: r123 - r0 (reversed)
# 252: _closure, 253: _context, 254-255: reserved
def _byte_to_register(val):
    if val == 0:
        return "Wide"
    if val == 1:
        return "ExtraWide"
    if 2 <= val <= 127:
        return "a%d" % (val - 2)
    if 128 <= val <= 251:
        return "r%d" % (251 - val)
    if val == 252:
        return "_closure"
    if val == 253:
        return "_context"
    return "??(%d)" % val


def disassemble_bytecode(bytecode, constant_pool=None, handler_table=None):
    """Disassemble V8 bytecode bytes into instruction list.

    Returns list of (offset, mnemonic, operands_str, raw_bytes, comment)
    """
    instructions = []
    pos = 0
    length = len(bytecode)

    while pos < length:
        inst_start = pos
        opcode = bytecode[pos]
        pos += 1

        # Handle Wide/ExtraWide prefixes
        operand_size = 1  # default: 1 byte per operand
        prefix_name = None

        if opcode == 0x00:  # Wide
            if pos >= length:
                break
            prefix_name = "Wide"
            operand_size = 2
            opcode = bytecode[pos]
            pos += 1
        elif opcode == 0x01:  # ExtraWide
            if pos >= length:
                break
            prefix_name = "ExtraWide"
            operand_size = 4
            opcode = bytecode[pos]
            pos += 1

        if opcode not in OPCODES:
            instructions.append((inst_start, "UNKNOWN", "0x%02X" % opcode, bytecode[inst_start:pos], ""))
            continue

        mnemonic, operand_types = OPCODES[opcode]
        if prefix_name:
            mnemonic = "%s.%s" % (prefix_name, mnemonic)

        operands = []
        operand_strs = []
        comment = ""

        for op_type in operand_types:
            if op_type == kRuntimeId:
                # Always 2 bytes for runtime ID
                if pos + 2 <= length:
                    val = struct.unpack_from("<H", bytecode, pos)[0]
                    pos += 2
                else:
                    val = 0
                    pos = length
                operands.append((op_type, val))
                operand_strs.append("[%d]" % val)

            elif op_type == kRegRange:
                # Register + count (2 operands consumed)
                if operand_size == 1:
                    reg_byte = bytecode[pos] if pos < length else 0
                    pos += 1
                    count = bytecode[pos] if pos < length else 0
                    pos += 1
                elif operand_size == 2:
                    reg_byte = struct.unpack_from("<H", bytecode, pos)[0] if pos + 2 <= length else 0
                    pos += 2
                    count = struct.unpack_from("<H", bytecode, pos)[0] if pos + 2 <= length else 0
                    pos += 2
                else:
                    reg_byte = struct.unpack_from("<I", bytecode, pos)[0] if pos + 4 <= length else 0
                    pos += 4
                    count = struct.unpack_from("<I", bytecode, pos)[0] if pos + 4 <= length else 0
                    pos += 4
                reg_name = _byte_to_register(reg_byte & 0xFF)
                operands.append((op_type, (reg_byte, count)))
                operand_strs.append("%s-%s(%d)" % (reg_name, _byte_to_register((reg_byte + count - 1) & 0xFF) if count > 0 else reg_name, count))

            elif op_type == kRegPair:
                if operand_size == 1:
                    reg_byte = bytecode[pos] if pos < length else 0
                    pos += 1
                elif operand_size == 2:
                    reg_byte = struct.unpack_from("<H", bytecode, pos)[0] if pos + 2 <= length else 0
                    pos += 2
                else:
                    reg_byte = struct.unpack_from("<I", bytecode, pos)[0] if pos + 4 <= length else 0
                    pos += 4
                reg_name = _byte_to_register(reg_byte & 0xFF)
                operands.append((op_type, reg_byte))
                operand_strs.append("%s(pair)" % reg_name)

            elif op_type == kRegTriple:
                if operand_size == 1:
                    reg_byte = bytecode[pos] if pos < length else 0
                    pos += 1
                elif operand_size == 2:
                    reg_byte = struct.unpack_from("<H", bytecode, pos)[0] if pos + 2 <= length else 0
                    pos += 2
                else:
                    reg_byte = struct.unpack_from("<I", bytecode, pos)[0] if pos + 4 <= length else 0
                    pos += 4
                reg_name = _byte_to_register(reg_byte & 0xFF)
                operands.append((op_type, reg_byte))
                operand_strs.append("%s(triple)" % reg_name)

            else:
                # Standard operand: read operand_size bytes
                if operand_size == 1:
                    if pos >= length:
                        val = 0
                        pos = length
                    else:
                        val = bytecode[pos]
                        pos += 1
                elif operand_size == 2:
                    if pos + 2 > length:
                        val = 0
                        pos = length
                    else:
                        val = struct.unpack_from("<H", bytecode, pos)[0]
                        pos += 2
                else:  # 4
                    if pos + 4 > length:
                        val = 0
                        pos = length
                    else:
                        val = struct.unpack_from("<I", bytecode, pos)[0]
                        pos += 4

                operands.append((op_type, val))

                if op_type == kReg:
                    operand_strs.append(_byte_to_register(val & 0xFF))
                elif op_type == kImm:
                    # Sign extend
                    if operand_size == 1 and val > 127:
                        val = val - 256
                    elif operand_size == 2 and val > 32767:
                        val = val - 65536
                    operand_strs.append("[%d]" % val)
                elif op_type == kIdx:
                    operand_strs.append("[%d]" % val)
                elif op_type == kUImm:
                    operand_strs.append("[%d]" % val)
                elif op_type == kFlag8:
                    operand_strs.append("#%d" % val)
                elif op_type == kIntrinsicId:
                    operand_strs.append("[%d]" % val)

        # Build comment for jump targets
        base_mnemonic = mnemonic.split(".")[-1] if "." in mnemonic else mnemonic

        if base_mnemonic in FORWARD_JUMPS:
            for op_type, val in operands:
                if op_type == kUImm:
                    target = inst_start + val
                    comment = "-> @%04X" % target
                    break

        elif base_mnemonic in BACKWARD_JUMPS:
            for op_type, val in operands:
                if op_type == kUImm:
                    target = inst_start - val
                    comment = "-> @%04X" % target
                    break

        # Add constant pool value comments
        if constant_pool is not None:
            for op_type, val in operands:
                if op_type == kIdx and val < len(constant_pool.items):
                    cp_val = constant_pool.items[val]
                    if isinstance(cp_val, str):
                        comment += ' ; "%s"' % cp_val[:60]
                    elif isinstance(cp_val, (int, float)):
                        comment += " ; %s" % repr(cp_val)
                    elif hasattr(cp_val, "name"):
                        comment += " ; %s" % cp_val.name
                    break

        # TestTypeOf literal names
        if base_mnemonic == "TestTypeOf":
            for op_type, val in operands:
                if op_type == kFlag8 and val < len(TYPEOF_LITERALS):
                    comment = "; %s" % TYPEOF_LITERALS[val]
                    break

        raw_bytes = bytecode[inst_start:pos]
        instructions.append((inst_start, mnemonic, " ".join(operand_strs), raw_bytes, comment))

    return instructions
