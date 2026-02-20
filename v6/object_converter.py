import struct

from common.reserv_object import ReservObject, RootObject


def _int_to_bytes_le(val):
    return struct.pack("<I", val & 0xFFFFFFFF)


def two_ints_to_double(x1, x2):
    data = struct.pack("<II", x1 & 0xFFFFFFFF, x2 & 0xFFFFFFFF)
    return struct.unpack("<d", data)[0]


def reserv_object_to_bytes(obj, len_dword_index, is_16le, pointer_size):
    length = obj.get_smi_int(len_dword_index * pointer_size) * (2 if is_16le else 1)
    result = bytearray(length)

    for i in range(0, length, 4):
        tmp = _int_to_bytes_le(obj.get_int((len_dword_index + 1) * pointer_size + i))

        for j in range(4):
            if i + j < length:
                result[i + j] = tmp[j]
            else:
                break

    return bytes(result)


def convert_cons_one_byte_string(obj, pointer_size):
    if obj is None:
        return ""
    elif isinstance(obj, str):
        return obj
    elif isinstance(obj, RootObject):
        return obj.name
    elif isinstance(obj, ReservObject):
        type_obj = obj.get_aligned_object(0)
        if not isinstance(type_obj, RootObject):
            return ""
        type_name = type_obj.name

        if type_name in ("OneByteInternalizedString", "OneByteString"):
            return convert_reserv_object(obj, pointer_size)
        elif type_name == "ConsOneByteString":
            left = convert_cons_one_byte_string(obj.get_aligned_object(3 * pointer_size), pointer_size)
            right = convert_cons_one_byte_string(obj.get_aligned_object(4 * pointer_size), pointer_size)
            return left + right
    return ""


def convert_reserv_object(obj, pointer_size):
    type_obj = obj.get_aligned_object(0)
    if not isinstance(type_obj, RootObject):
        return None

    type_name = type_obj.name

    if type_name in ("OneByteInternalizedString", "OneByteString"):
        raw = reserv_object_to_bytes(obj, 2, False, pointer_size)
        return raw.decode("utf-8", errors="replace")

    elif type_name == "InternalizedString":
        raw = reserv_object_to_bytes(obj, 2, True, pointer_size)
        return raw.decode("utf-16-le", errors="replace")

    elif type_name == "ConsOneByteString":
        return convert_cons_one_byte_string(obj, pointer_size)

    elif type_name == "FixedCOWArray":
        count = (obj.get_size() - pointer_size) // 4
        result = []
        for i in range(count):
            result.append(obj.get_int(pointer_size + i * 4))
        return result

    elif type_name == "HeapNumber":
        return two_ints_to_double(obj.get_int(pointer_size), obj.get_int(pointer_size + 4))

    return None


class ConstantPoolRef:
    """Lightweight wrapper for constant pool items that are complex objects."""
    def __init__(self, type_name, name=""):
        self.type_name = type_name
        self.name = name or type_name

    def __repr__(self):
        return self.name


def _extract_sfi_name(obj, pointer_size):
    """Extract the function name from a SharedFunctionInfo ReservObject."""
    ps = pointer_size
    kNameOffset = ps + ps  # kMetaMap + kCodeOffset + kNameOffset
    name_obj = obj.get_aligned_object(kNameOffset)

    if isinstance(name_obj, RootObject):
        name = name_obj.name
    elif isinstance(name_obj, ReservObject):
        converted = convert_reserv_object(name_obj, ps)
        name = converted if converted else ""
    elif isinstance(name_obj, str):
        name = name_obj
    else:
        name = ""

    name = name.replace("empty_string", "")
    if not name:
        # Try to get function_literal_id
        kScriptOffset = _get_script_offset_calc(ps)
        kDebugInfoOffset = kScriptOffset + ps
        kFunctionIdentifierOffset = kDebugInfoOffset + ps
        kFeedbackMetadataOffset = kFunctionIdentifierOffset + ps
        kPreParsedScopeDataOffset = kFeedbackMetadataOffset + ps
        kFunctionLiteralIdOffset = kPreParsedScopeDataOffset + ps
        func_id = obj.get_int(kFunctionLiteralIdOffset)
        name = "func_%04d" % func_id

    return name


def _get_script_offset_calc(ps):
    kCodeOffset = ps
    kNameOffset = kCodeOffset + ps
    kScopeInfoOffset = kNameOffset + ps
    kOuterScopeInfoOffset = kScopeInfoOffset + ps
    kConstructStubOffset = kOuterScopeInfoOffset + ps
    kInstanceClassNameOffset = kConstructStubOffset + ps
    kFunctionDataOffset = kInstanceClassNameOffset + ps
    return kFunctionDataOffset + ps


def prepare_for_alloc(cp_obj, pointer_size):
    if isinstance(cp_obj, (int, float)):
        return cp_obj
    elif isinstance(cp_obj, RootObject):
        return cp_obj
    elif isinstance(cp_obj, ReservObject):
        type_obj = cp_obj.get_aligned_object(0)
        if not isinstance(type_obj, RootObject):
            return cp_obj

        type_name = type_obj.name

        if type_name in ("OneByteInternalizedString", "OneByteString", "InternalizedString"):
            return convert_reserv_object(cp_obj, pointer_size)
        elif type_name == "ConsOneByteString":
            return convert_cons_one_byte_string(cp_obj, pointer_size)
        elif type_name == "HeapNumber":
            return two_ints_to_double(cp_obj.get_int(pointer_size), cp_obj.get_int(pointer_size + 4))
        elif type_name in ("FixedArray", "FixedCOWArray"):
            result = convert_reserv_object(cp_obj, pointer_size)
            if result is not None:
                return result
            return ConstantPoolRef("FixedArray")
        elif type_name in ("Tuple2", "Tuple3"):
            return ConstantPoolRef(type_name)
        elif type_name == "SharedFunctionInfo":
            name = _extract_sfi_name(cp_obj, pointer_size)
            return ConstantPoolRef("SharedFunctionInfo", "<closure: %s>" % name)
        elif type_name == "ScopeInfo":
            return ConstantPoolRef("ScopeInfo")
        else:
            return ConstantPoolRef(type_name)

    return cp_obj
