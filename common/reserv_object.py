import struct
from collections import OrderedDict


class RootObject:
    __slots__ = ("name", "type")

    def __init__(self, name, obj_type):
        self.name = name
        self.type = obj_type

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        if not isinstance(other, RootObject):
            return NotImplemented
        return self.name == other.name and self.type == other.type

    def __hash__(self):
        return hash((self.name, self.type))


def _bytes_to_ints(data):
    count = len(data) // 4
    return list(struct.unpack_from("<%dI" % count, data))


def smi_to_int(value, pointer_size):
    if pointer_size == 4:
        return (value & 0xFFFFFFFF) >> 1
    return value >> 32


class ReservObject:
    def __init__(self, size, pointer_size):
        self.size = size
        self.pointer_size = pointer_size
        self._offset = 0
        self._last_add_address = 0
        self.objects = OrderedDict()

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    def get_last_object(self):
        return self.objects.get(self._last_add_address)

    def get_aligned_object(self, offset):
        obj = self.objects.get(offset)

        if self.pointer_size == 4:
            return obj

        if isinstance(obj, int) and not isinstance(obj, bool):
            obj2 = self.objects.get(offset + 4)
            if isinstance(obj2, int) and not isinstance(obj2, bool):
                return obj2 << 32
            return obj

        return obj

    def get_int(self, offset):
        val = self.objects.get(offset)
        if val is None:
            return 0
        if isinstance(val, int):
            return val & 0xFFFFFFFF
        return 0

    def get_smi_int(self, offset):
        obj1 = self.get_int(offset)

        if self.pointer_size == 4:
            return smi_to_int(obj1, self.pointer_size)

        obj2 = self.get_int(offset + 4)
        return smi_to_int(obj2 << 32, self.pointer_size)

    def add_object(self, address, obj):
        self._last_add_address = address

        if isinstance(obj, (bytes, bytearray)):
            ints = _bytes_to_ints(bytes(obj))
            for i, val in enumerate(ints):
                self.objects[address + i * 4] = val
        else:
            self.objects[address] = obj

    def get_size(self):
        return self.size

    def __repr__(self):
        lines = []
        for addr, val in self.objects.items():
            lines.append("%04X: %s" % (addr, val))
        return "\n".join(lines)
