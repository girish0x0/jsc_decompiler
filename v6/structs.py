import struct

from common.reserv_object import ReservObject, RootObject
from common.enums import ScopeInfoFlags
from v6.object_converter import (
    convert_reserv_object, convert_cons_one_byte_string,
    prepare_for_alloc, two_ints_to_double,
)


K_META_MAP = 0


def get_array_length_offset(pointer_size):
    return K_META_MAP + pointer_size


def get_array_header_size(pointer_size):
    return get_array_length_offset(pointer_size) + pointer_size


def get_script_offset(pointer_size):
    ps = pointer_size
    kCodeOffset = K_META_MAP + ps
    kNameOffset = kCodeOffset + ps
    kScopeInfoOffset = kNameOffset + ps
    kOuterScopeInfoOffset = kScopeInfoOffset + ps
    kConstructStubOffset = kOuterScopeInfoOffset + ps
    kInstanceClassNameOffset = kConstructStubOffset + ps
    kFunctionDataOffset = kInstanceClassNameOffset + ps
    return kFunctionDataOffset + ps


def get_function_literal_id_offset(pointer_size):
    kScriptOffset = get_script_offset(pointer_size)
    kDebugInfoOffset = kScriptOffset + pointer_size
    kFunctionIdentifierOffset = kDebugInfoOffset + pointer_size
    kFeedbackMetadataOffset = kFunctionIdentifierOffset + pointer_size
    kPreParsedScopeDataOffset = kFeedbackMetadataOffset + pointer_size
    return kPreParsedScopeDataOffset + pointer_size


class HandlerTableEntry:
    def __init__(self, start, end, prediction, handler_offset, data):
        self.start = start
        self.end = end
        self.prediction = prediction
        self.handler_offset = handler_offset
        self.data = data

    def __repr__(self):
        return ("HandlerEntry(start=%d, end=%d, handler=%d, pred=%d, data=%d)" %
                (self.start, self.end, self.handler_offset, self.prediction, self.data))


class HandlerTable:
    def __init__(self, obj, pointer_size):
        arr_len_off = get_array_length_offset(pointer_size)
        arr_hdr_size = get_array_header_size(pointer_size)

        count = obj.get_smi_int(arr_len_off) // 4
        self.entries = []

        for i in range(count):
            start = obj.get_smi_int(arr_hdr_size + (4 * i + 0) * pointer_size)
            end = obj.get_smi_int(arr_hdr_size + (4 * i + 1) * pointer_size)
            handler = obj.get_smi_int(arr_hdr_size + (4 * i + 2) * pointer_size)
            data = obj.get_smi_int(arr_hdr_size + (4 * i + 3) * pointer_size)

            prediction = handler & 7
            handler_offset = handler >> 3

            self.entries.append(HandlerTableEntry(start, end, prediction, handler_offset, data))


class ConstantPool:
    def __init__(self, obj, pointer_size):
        arr_len_off = get_array_length_offset(pointer_size)
        arr_hdr_size = get_array_header_size(pointer_size)

        self.count = obj.get_smi_int(arr_len_off)
        self.items = []

        for i in range(self.count):
            raw = obj.get_aligned_object(arr_hdr_size + i * pointer_size)
            item = prepare_for_alloc(raw, pointer_size)
            self.items.append(item)


class BytecodeData:
    def __init__(self, obj, pointer_size):
        arr_len_off = get_array_length_offset(pointer_size)
        arr_hdr_size = get_array_header_size(pointer_size)

        kConstantPoolOffset = arr_hdr_size
        kHandlerTableOffset = kConstantPoolOffset + pointer_size
        kSourcePositionTableOffset = kHandlerTableOffset + pointer_size
        kFrameSizeOffset = kSourcePositionTableOffset + pointer_size
        kParameterSizeOffset = kFrameSizeOffset + 4
        kIncomingNewTargetOrGeneratorRegisterOffset = kParameterSizeOffset + 4
        kInterruptBudgetOffset = kIncomingNewTargetOrGeneratorRegisterOffset + 4
        kOSRNestingLevelOffset = kInterruptBudgetOffset + 4
        kBytecodeAgeOffset = kOSRNestingLevelOffset + 1
        kHeaderSize = kBytecodeAgeOffset + 1 + 2

        self.length = obj.get_smi_int(arr_len_off)
        self.frame_size = obj.get_int(kFrameSizeOffset)
        self.parameter_size = obj.get_int(kParameterSizeOffset) // pointer_size

        # Constant pool
        cp_obj = obj.get_aligned_object(kConstantPoolOffset)
        if isinstance(cp_obj, ReservObject):
            self.constant_pool = ConstantPool(cp_obj, pointer_size)
        else:
            self.constant_pool = None

        # Handler table
        ht_obj = obj.get_aligned_object(kHandlerTableOffset)
        if isinstance(ht_obj, ReservObject):
            self.handler_table = HandlerTable(ht_obj, pointer_size)
        else:
            self.handler_table = None

        # Extract bytecode bytes
        # First 2 bytes come from bits 16-31 of the dword at kOSRNestingLevelOffset
        # Remaining length-2 bytes come from dwords at kHeaderSize onwards
        tmp = obj.get_int(kOSRNestingLevelOffset)
        bytecode = bytearray()
        bytecode.append((tmp >> 16) & 0xFF)
        bytecode.append((tmp >> 24) & 0xFF)

        remaining = self.length - 2
        for i in range(0, remaining, 4):
            dw = obj.get_int(kHeaderSize + i)
            b = struct.pack("<I", dw & 0xFFFFFFFF)
            bytecode.extend(b)

        self.bytecode = bytes(bytecode[:self.length])


class ScopeInfo:
    def __init__(self, obj, pointer_size, scope_cache=None):
        ps = pointer_size

        kFlagsOffset = ps + ps
        kParameterCount = kFlagsOffset + ps
        kStackLocalCount = kParameterCount + ps
        kContextLocalCount = kStackLocalCount + ps
        kParamsOffset = kContextLocalCount + ps

        self.flags_raw = obj.get_smi_int(kFlagsOffset)
        self.flags = ScopeInfoFlags(self.flags_raw)

        self.params_count = obj.get_smi_int(kParameterCount)
        self.stack_locals_count = obj.get_smi_int(kStackLocalCount)
        self.context_locals_count = obj.get_smi_int(kContextLocalCount)

        offset = kParamsOffset

        # Read parameter names
        self.params = []
        for i in range(self.params_count):
            param = obj.get_aligned_object(offset)
            if isinstance(param, RootObject):
                self.params.append(param.name)
            elif isinstance(param, ReservObject):
                converted = convert_reserv_object(param, ps)
                self.params.append(converted if converted else "")
            elif isinstance(param, str):
                self.params.append(param)
            else:
                self.params.append("")
            offset += ps

        # Stack locals first slot
        self.stack_locals_first_slot = obj.get_smi_int(offset)
        offset += ps

        # Read stack local names
        self.stack_locals = []
        for i in range(self.stack_locals_count):
            stack_obj = obj.get_aligned_object(offset)
            if isinstance(stack_obj, RootObject):
                self.stack_locals.append(stack_obj.name)
            elif isinstance(stack_obj, ReservObject):
                converted = convert_reserv_object(stack_obj, ps)
                self.stack_locals.append(converted if converted else "")
            elif isinstance(stack_obj, str):
                self.stack_locals.append(stack_obj)
            else:
                self.stack_locals.append("")
            offset += ps

        # Context locals
        self.context_locals = []
        if self.context_locals_count > 0:
            for i in range(self.context_locals_count):
                ctx_local = obj.get_aligned_object(offset)
                if isinstance(ctx_local, RootObject):
                    self.context_locals.append(ctx_local.name)
                elif isinstance(ctx_local, ReservObject):
                    converted = convert_reserv_object(ctx_local, ps)
                    self.context_locals.append(converted if converted else "")
                elif isinstance(ctx_local, str):
                    self.context_locals.append(ctx_local)
                else:
                    self.context_locals.append("")
                offset += ps

            # Skip context local infos (varInfo Smis)
            offset += self.context_locals_count * ps

        # Receiver
        self.receiver = None
        if self.flags.has_receiver():
            self.receiver = obj.get_int(offset)
            offset += ps

        # FuncVar
        self.func_var = None
        if self.flags.has_function_var():
            self.func_var = obj.get_int(offset)
            offset += ps  # mode
            # name follows
            offset += ps

        # Outer scope
        self.outer_scope = None
        if self.flags.has_outer_scope():
            outer_obj = obj.get_aligned_object(offset)
            if isinstance(outer_obj, ReservObject) and scope_cache is not None:
                obj_id = id(outer_obj)
                if obj_id not in scope_cache:
                    scope_cache[obj_id] = ScopeInfo(outer_obj, ps, scope_cache)
                self.outer_scope = scope_cache[obj_id]
            offset += ps


class SharedFunctionInfo:
    def __init__(self, obj, pointer_size, scope_cache=None):
        ps = pointer_size

        kCodeOffset = K_META_MAP + ps
        kNameOffset = kCodeOffset + ps
        kScopeInfoOffset = kNameOffset + ps
        kOuterScopeInfoOffset = kScopeInfoOffset + ps
        kConstructStubOffset = kOuterScopeInfoOffset + ps
        kInstanceClassNameOffset = kConstructStubOffset + ps
        kFunctionDataOffset = kInstanceClassNameOffset + ps
        kScriptOffset = kFunctionDataOffset + ps
        kDebugInfoOffset = kScriptOffset + ps
        kFunctionIdentifierOffset = kDebugInfoOffset + ps
        kFeedbackMetadataOffset = kFunctionIdentifierOffset + ps
        kPreParsedScopeDataOffset = kFeedbackMetadataOffset + ps
        kFunctionLiteralIdOffset = kPreParsedScopeDataOffset + ps
        kLengthOffset = kFunctionLiteralIdOffset + 4
        kFormalParameterCountOffset = kLengthOffset + 4
        kExpectedNofPropertiesOffset = kFormalParameterCountOffset + 4
        kStartPositionAndTypeOffset = kExpectedNofPropertiesOffset + 4
        kEndPositionOffset = kStartPositionAndTypeOffset + 4
        kFunctionTokenPositionOffset = kEndPositionOffset + 4
        kCompilerHintsOffset = kFunctionTokenPositionOffset + 4

        self.function_literal_id = obj.get_int(kFunctionLiteralIdOffset)
        self.function_length = obj.get_int(kLengthOffset)
        self.formal_parameter_count = obj.get_int(kFormalParameterCountOffset)
        self.expected_nof_properties = obj.get_int(kExpectedNofPropertiesOffset)
        self.start_position_and_type = obj.get_int(kStartPositionAndTypeOffset)
        self.end_position = obj.get_int(kEndPositionOffset)
        self.function_token_position = obj.get_int(kFunctionTokenPositionOffset)
        self.compiler_hints = obj.get_int(kCompilerHintsOffset)

        # Code offset (builtin name)
        self.code_offset = obj.get_aligned_object(kCodeOffset)

        # Name
        name_obj = obj.get_aligned_object(kNameOffset)
        if isinstance(name_obj, RootObject):
            self.name = name_obj.name
        elif isinstance(name_obj, ReservObject):
            converted = convert_reserv_object(name_obj, ps)
            self.name = converted if converted else ""
        elif isinstance(name_obj, str):
            self.name = name_obj
        elif isinstance(name_obj, int) and name_obj == 0:
            self.name = "empty_string"
        else:
            self.name = ""

        # Clean up name
        self.name = self.name.replace(" ", "_").replace("empty_string", "")
        if not self.name:
            self.name = "func_%04d" % self.function_literal_id

        # Scope info
        scope_obj = obj.get_aligned_object(kScopeInfoOffset)
        if isinstance(scope_obj, ReservObject):
            if scope_cache is None:
                scope_cache = {}
            obj_id = id(scope_obj)
            if obj_id not in scope_cache:
                scope_cache[obj_id] = ScopeInfo(scope_obj, ps, scope_cache)
            self.scope_info = scope_cache[obj_id]
        else:
            self.scope_info = None

        # Outer scope info
        outer_scope_obj = obj.get_aligned_object(kOuterScopeInfoOffset)
        if isinstance(outer_scope_obj, ReservObject):
            if scope_cache is None:
                scope_cache = {}
            obj_id = id(outer_scope_obj)
            if obj_id not in scope_cache:
                scope_cache[obj_id] = ScopeInfo(outer_scope_obj, ps, scope_cache)
            self.outer_scope_info = scope_cache[obj_id]
        else:
            self.outer_scope_info = None

        # Bytecode data
        bc_obj = obj.get_aligned_object(kFunctionDataOffset)
        if isinstance(bc_obj, ReservObject):
            self.bytecode = BytecodeData(bc_obj, ps)
        else:
            self.bytecode = None

        # Identifier
        ident_obj = obj.get_aligned_object(kFunctionIdentifierOffset)
        if isinstance(ident_obj, RootObject):
            self.identifier = ident_obj.name
        elif isinstance(ident_obj, ReservObject):
            converted = convert_reserv_object(ident_obj, ps)
            self.identifier = converted if converted else ""
        elif isinstance(ident_obj, str):
            self.identifier = ident_obj
        else:
            self.identifier = ""

    def __repr__(self):
        return "SharedFunctionInfo(%s, id=%d, params=%d)" % (
            self.name, self.function_literal_id, self.formal_parameter_count)
