from enum import IntEnum
from dataclasses import dataclass


class AllocSpace(IntEnum):
    NEW_SPACE = 0x00
    OLD_SPACE = 0x01
    CODE_SPACE = 0x02
    MAP_SPACE = 0x03
    LO_SPACE = 0x04

    @classmethod
    def from_int(cls, value):
        for member in cls:
            if member.value == value:
                return member
        return None


class AllocWhere(IntEnum):
    kNewObject = 0x00
    kBackref = 0x08
    kBackrefWithSkip = 0x10
    kRootArray = 0x05
    kPartialSnapshotCache = 0x06
    kExternalReference = 0x07
    kAttachedReference = 0x0D
    kBuiltin = 0x0E


class AllocHow(IntEnum):
    kPlain = 0x00
    kFromCode = 0x20


class AllocPoint(IntEnum):
    kStartOfObject = 0x00
    kInnerPointer = 0x40


class AllocationAlignment(IntEnum):
    kWordAligned = 0
    kDoubleAligned = 1
    kDoubleUnaligned = 2

    @classmethod
    def from_int(cls, value):
        for member in cls:
            if member.value == value:
                return member
        return None


class ScopeInfoFlagsScope(IntEnum):
    EVAL_SCOPE = 0
    FUNCTION_SCOPE = 1
    MODULE_SCOPE = 2
    SCRIPT_SCOPE = 3
    CATCH_SCOPE = 4
    BLOCK_SCOPE = 5
    WITH_SCOPE = 6

    @classmethod
    def from_int(cls, value):
        for member in cls:
            if member.value == value:
                return member
        return None


class ScopeInfoFlagsReceiver(IntEnum):
    NONE = 0
    STACK = 1
    CONTEXT = 2
    UNUSED = 3

    @classmethod
    def from_int(cls, value):
        for member in cls:
            if member.value == value:
                return member
        return None


class ScopeInfoFlagsFuncVar(IntEnum):
    NONE = 0
    STACK = 1
    CONTEXT = 2
    UNUSED = 3

    @classmethod
    def from_int(cls, value):
        for member in cls:
            if member.value == value:
                return member
        return None


class ScopeInfoFlagsLang(IntEnum):
    SLOPPY = 0
    STRICT = 1

    @classmethod
    def from_int(cls, value):
        for member in cls:
            if member.value == value:
                return member
        return None


class ScopeInfoFlagsFuncKind(IntEnum):
    NormalFunction = 0
    ArrowFunction = 1
    GeneratorFunction = 2
    ConciseMethod = 4
    ConciseGeneratorMethod = 6
    DefaultConstructor = 8
    DerivedConstructor = 16
    BaseConstructor = 32
    GetterFunction = 64
    SetterFunction = 128
    AsyncFunction = 256
    Module = 512
    AccessorFunction = 192
    DefaultBaseConstructor = 40
    DefaultDerivedConstructor = 24
    ClassConstructor = 56
    AsyncArrowFunction = 257
    AsyncConciseMethod = 260
    AsyncConciseGeneratorMethod = 262
    AsyncGeneratorFunction = 258

    @classmethod
    def from_int(cls, value):
        for member in cls:
            if member.value == value:
                return member
        return None


@dataclass
class CaseState:
    value: int
    where: AllocWhere
    how: AllocHow
    within: AllocPoint


def case_statement(state):
    return state.where.value + state.how.value + state.within.value


class ScopeInfoFlags:
    def __init__(self, flags):
        self.scope = ScopeInfoFlagsScope.from_int(flags & 0xF)
        self.calls_sloppy_eval = ((flags & 0x10) >> 0x04) != 0
        self.lang_mode = ScopeInfoFlagsLang.from_int((flags & 0x20) >> 0x05)
        self.declaration_scope = ((flags & 0x40) >> 0x06) != 0
        self.recv = ScopeInfoFlagsReceiver.from_int((flags & 0x180) >> 0x07)
        self.has_new_target = ((flags & 0x200) >> 0x09) != 0
        self.func_var = ScopeInfoFlagsFuncVar.from_int((flags & 0xC00) >> 0x0A)
        self.asm_module = ((flags & 0x1000) >> 0x0C) != 0
        self.has_simple_parameters = ((flags & 0x2000) >> 0x0D) != 0
        self.kind = ScopeInfoFlagsFuncKind.from_int((flags & 0x00FFC000) >> 0x0E)
        self.has_outer_scope_info = ((flags & 0x01000000) >> 0x18) != 0
        self.is_debug_evaluate_scope = ((flags & 0x02000000) >> 0x19) != 0

    def has_receiver(self):
        return self.recv not in (ScopeInfoFlagsReceiver.UNUSED, ScopeInfoFlagsReceiver.NONE)

    def has_function_var(self):
        return self.func_var != ScopeInfoFlagsFuncVar.NONE

    def has_outer_scope(self):
        return self.has_outer_scope_info
