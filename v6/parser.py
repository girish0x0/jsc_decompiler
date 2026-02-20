import json
import os
import struct

from common.enums import (
    AllocSpace, AllocWhere, AllocHow, AllocPoint,
    AllocationAlignment, CaseState, case_statement,
)
from common.reserv_object import ReservObject, RootObject


class BinaryReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read_uint32(self):
        val = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_byte(self):
        val = self.data[self.pos]
        self.pos += 1
        return val

    def read_bytes(self, count):
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result

    def seek(self, pos):
        self.pos = pos


class JscParser:
    def __init__(self, data, is_32bit):
        self.reader = BinaryReader(data)
        self.is_32bit = is_32bit

        self.kPointerSizeLog2 = 2 if is_32bit else 3
        self.kPointerSize = 4 if is_32bit else 8
        self.kPointerAlignment = 1 << self.kPointerSizeLog2
        self.kPointerAlignmentMask = self.kPointerAlignment - 1
        self.kObjectAlignmentBits = self.kPointerSizeLog2

        self.attached = ["Source"]
        self.builtins = []
        self.roots = []

        self.next_alignment = AllocationAlignment.kWordAligned
        self.last_hot_index = 0
        self.last_chunk_index = {}
        self.hots = {}

        self.reserv = {}
        self.code_stubs = []

        self.version_hash = 0
        self.source_hash = 0

    def _pointer_size_align(self, value):
        return (value + self.kPointerAlignmentMask) & ~self.kPointerAlignmentMask

    def load_metadata(self, data_dir=None):
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

        with open(os.path.join(data_dir, "v8_roots.json"), "r") as f:
            roots_data = json.load(f)
        for item in roots_data:
            self.roots.append(RootObject(item["Name"], item["Type"]))

        with open(os.path.join(data_dir, "v8_builtins.json"), "r") as f:
            self.builtins = json.load(f)

        with open(os.path.join(data_dir, "v8_funcs.json"), "r") as f:
            self.funcs_data = json.load(f)

        with open(os.path.join(data_dir, "v8_jsruns.json"), "r") as f:
            self.jsruns_data = json.load(f)

    def parse(self):
        reader = self.reader

        magic = reader.read_uint32()
        if magic not in (0xC0DE0BEE, 0xC0DE03BE, 0xC0DE0628):
            raise ValueError("Invalid JSC magic: 0x%08X" % magic)

        self.version_hash = reader.read_uint32()
        self.source_hash = reader.read_uint32()
        cpu_features = reader.read_uint32()
        flags_hash = reader.read_uint32()

        reserv_count = reader.read_uint32()
        reserv_size = reserv_count * 4
        code_stubs_count = reader.read_uint32()
        code_stubs_size = code_stubs_count * 4
        payload_size = reader.read_uint32()

        c1 = reader.read_uint32()
        c2 = reader.read_uint32()

        payload_offset = self._pointer_size_align(reader.pos + reserv_size + code_stubs_size)

        curr_space = 0
        for i in range(reserv_count):
            space = AllocSpace.from_int(curr_space)

            if space not in self.reserv:
                self.reserv[space] = []

            size = reader.read_uint32()
            self.reserv[space].append(ReservObject(size & 0x7FFFFFFF, self.kPointerSize))
            self.last_chunk_index[space] = 0

            if (size & 0x80000000) >> 0x1F != 0:
                curr_space += 1

        for i in range(code_stubs_count):
            self.code_stubs.append(reader.read_uint32())

        reader.seek(payload_offset)

        root = ReservObject(self.kPointerSize, self.kPointerSize)
        self._read_data(root, root.get_size(), AllocSpace.NEW_SPACE, 0)
        self._deserialize_deferred_objects()

        results = []
        old_space_chunks = self.reserv.get(AllocSpace.OLD_SPACE, [])
        for chunk in old_space_chunks:
            funcs = self._load_space_objects(chunk)
            if funcs:
                results.extend(funcs)

        return results

    def _load_space_objects(self, space_objs):
        first_func = space_objs.get_aligned_object(0)
        if first_func is None:
            return None
        if not isinstance(first_func, ReservObject):
            return None

        kPointerSize = self.kPointerSize
        script_offset = self._get_script_offset()
        script = first_func.get_aligned_object(script_offset)
        if not isinstance(script, ReservObject):
            return None

        shared_funcs = script.get_aligned_object(12 * kPointerSize)
        if not isinstance(shared_funcs, ReservObject):
            return None

        array_length_offset = kPointerSize  # kMetaMap(0) + pointerSize
        array_header_size = array_length_offset + kPointerSize

        sf_count = shared_funcs.get_smi_int(array_length_offset)

        functions = []
        for i in range(sf_count):
            weak_func = shared_funcs.get_aligned_object(array_header_size + i * kPointerSize)
            if not isinstance(weak_func, ReservObject):
                continue
            func = weak_func.get_aligned_object(kPointerSize)
            if not isinstance(func, ReservObject):
                continue
            functions.append(func)

        return functions

    def _get_script_offset(self):
        ps = self.kPointerSize
        kCodeOffset = ps  # kMetaMap(0) + ps
        kNameOffset = kCodeOffset + ps
        kScopeInfoOffset = kNameOffset + ps
        kOuterScopeInfoOffset = kScopeInfoOffset + ps
        kConstructStubOffset = kOuterScopeInfoOffset + ps
        kInstanceClassNameOffset = kConstructStubOffset + ps
        kFunctionDataOffset = kInstanceClassNameOffset + ps
        return kFunctionDataOffset + ps

    def _deserialize_deferred_objects(self):
        while True:
            b = self.reader.read_byte() & 0xFF

            if b in (0x15, 0x16, 0x17):  # kAlignmentPrefix
                self.next_alignment = AllocationAlignment.from_int(b - (0x15 - 1))
            elif b == 0x18:  # kSynchronize
                return
            else:
                space = AllocSpace.from_int(b & 7)
                back_obj = self._get_back_referenced_object(space)

                size = self._read_int() << self.kPointerSizeLog2
                if isinstance(back_obj, ReservObject):
                    self._read_data(back_obj, size, space, self.kPointerSize)

    def _read_data(self, obj, size, space, start_insert):
        insert_off = start_insert

        while insert_off < size:
            b = self.reader.read_byte() & 0xFF

            # Try all 13 (where, how, within) combinations
            result = self._do_all_spaces(insert_off, b, obj,
                                         AllocWhere.kNewObject, AllocHow.kPlain, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            result = self._do_all_spaces(insert_off, b, obj,
                                         AllocWhere.kNewObject, AllocHow.kFromCode, AllocPoint.kInnerPointer)
            if result != -1:
                insert_off = result
                continue

            result = self._do_all_spaces(insert_off, b, obj,
                                         AllocWhere.kBackref, AllocHow.kPlain, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            result = self._do_all_spaces(insert_off, b, obj,
                                         AllocWhere.kBackrefWithSkip, AllocHow.kPlain, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            result = self._do_all_spaces(insert_off, b, obj,
                                         AllocWhere.kBackref, AllocHow.kFromCode, AllocPoint.kInnerPointer)
            if result != -1:
                insert_off = result
                continue

            result = self._do_all_spaces(insert_off, b, obj,
                                         AllocWhere.kBackrefWithSkip, AllocHow.kFromCode, AllocPoint.kInnerPointer)
            if result != -1:
                insert_off = result
                continue

            result = self._do_new_space(insert_off, b, obj,
                                        AllocWhere.kRootArray, AllocHow.kPlain, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            result = self._do_new_space(insert_off, b, obj,
                                        AllocWhere.kExternalReference, AllocHow.kPlain, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            result = self._do_new_space(insert_off, b, obj,
                                        AllocWhere.kExternalReference, AllocHow.kFromCode, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            result = self._do_new_space(insert_off, b, obj,
                                        AllocWhere.kAttachedReference, AllocHow.kPlain, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            result = self._do_new_space(insert_off, b, obj,
                                        AllocWhere.kAttachedReference, AllocHow.kFromCode, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            result = self._do_new_space(insert_off, b, obj,
                                        AllocWhere.kAttachedReference, AllocHow.kFromCode, AllocPoint.kInnerPointer)
            if result != -1:
                insert_off = result
                continue

            result = self._do_new_space(insert_off, b, obj,
                                        AllocWhere.kBuiltin, AllocHow.kPlain, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            result = self._do_new_space(insert_off, b, obj,
                                        AllocWhere.kBuiltin, AllocHow.kFromCode, AllocPoint.kStartOfObject)
            if result != -1:
                insert_off = result
                continue

            # Special opcodes
            if b == 0x0F:  # kSkip
                insert_off += self._read_int()
            elif b in (0x1B, 0x1C):  # kInternalReferenceEncoded, kInternalReference
                pass  # skip
            elif b == 0x2F:  # kNop
                return
            elif b == 0x4F:  # kNextChunk
                new_chunk = self.reader.read_byte() & 0xFF
                self.last_chunk_index[space] = new_chunk
            elif b == 0x6F:  # kDeferred
                insert_off = size
            elif b == 0x18:  # kSynchronize
                pass  # skip
            elif b == 0x1A:  # kVariableRawData
                size_in_bytes = self._read_int()
                raw_data = self.reader.read_bytes(size_in_bytes)
                obj.add_object(insert_off, raw_data)
            elif b == 0x19:  # kVariableRepeat
                repeats = self._read_int()
                last_obj = obj.get_last_object()
                insert_off = self._repeat_object(obj, insert_off, last_obj, repeats)
            elif b in (0x15, 0x16, 0x17):  # kAlignmentPrefix
                self.next_alignment = AllocationAlignment.from_int(b - (0x15 - 1))
            elif 0xA0 <= b <= 0xBF:  # kRootArrayConstantsWithSkip
                pass  # unimplemented in original
            elif 0x80 <= b <= 0x9F:  # kRootArrayConstants
                obj.add_object(insert_off, self.roots[b & 0x1F])
                insert_off += self.kPointerSize
            elif 0x58 <= b <= 0x5F:  # kHotObjectsWithSkip
                pass  # unimplemented in original
            elif 0x38 <= b <= 0x3F:  # kHotObject
                hot = self.hots.get(b & 7)
                obj.add_object(insert_off, hot)
                insert_off += self.kPointerSize
            elif 0xC0 <= b <= 0xDF:  # kFixedRawData
                size_in_bytes = (b - (0xC0 - 1)) << self.kPointerSizeLog2
                raw_data = self.reader.read_bytes(size_in_bytes)
                obj.add_object(insert_off, raw_data)
                insert_off += size_in_bytes
            elif 0xE0 <= b <= 0xEF:  # kFixedRepeat
                repeats = b - (0xE0 - 1)
                last_obj = obj.get_last_object()
                insert_off = self._repeat_object(obj, insert_off, last_obj, repeats)
            else:
                raise ValueError("Wrong JSC byte data: 0x%02X at pos 0x%X" % (b, self.reader.pos - 1))

    def _repeat_object(self, insert_obj, insert_off, last_obj, count):
        for _ in range(count):
            insert_obj.add_object(insert_off, last_obj)
            insert_off += self.kPointerSize
        return insert_off

    def _do_all_spaces(self, insert_off, val, obj, where, how, within):
        state = CaseState(val, where, how, within)
        space = self._all_spaces(state)
        if space is None:
            return -1

        if space in (AllocSpace.OLD_SPACE, AllocSpace.CODE_SPACE, AllocSpace.MAP_SPACE, AllocSpace.LO_SPACE):
            insert_off = self._read_space_data(obj, insert_off, state, None)
        elif space == AllocSpace.NEW_SPACE:
            insert_off = self._read_space_data(obj, insert_off, state, AllocSpace.NEW_SPACE)

        return insert_off

    def _do_new_space(self, insert_off, val, obj, where, how, within):
        state = CaseState(val, where, how, within)
        if not self._new_space(state):
            return -1
        return self._read_space_data(obj, insert_off, state, AllocSpace.NEW_SPACE)

    def _read_space_data(self, obj, insert_off, state, space):
        if space is None:
            space = AllocSpace.from_int(state.value & 7)

        where = state.where

        if where == AllocWhere.kNewObject and state.how == AllocHow.kPlain and state.within == AllocPoint.kStartOfObject:
            self._read_object(obj, insert_off, space)
        else:
            if where == AllocWhere.kNewObject:
                pass  # TODO
            elif where == AllocWhere.kBackref:
                back_obj = self._get_back_referenced_object(AllocSpace.from_int(state.value & 7))
                obj.add_object(insert_off, back_obj)
            elif where == AllocWhere.kBackrefWithSkip:
                pass  # TODO
            elif where == AllocWhere.kRootArray:
                idx = self._read_int()
                hot_obj = self.roots[idx]
                self.hots[self.last_hot_index] = hot_obj
                self.last_hot_index = (self.last_hot_index + 1) & 7
                obj.add_object(insert_off, hot_obj)
            elif where == AllocWhere.kPartialSnapshotCache:
                pass  # TODO
            elif where == AllocWhere.kExternalReference:
                pass  # TODO
            elif where == AllocWhere.kAttachedReference:
                index = self._read_int()
                if index < len(self.attached):
                    obj.add_object(insert_off, self.attached[index])
            elif where == AllocWhere.kBuiltin:
                idx = self._read_int()
                if idx < len(self.builtins):
                    obj.add_object(insert_off, self.builtins[idx])

        return insert_off + self.kPointerSize

    def _get_back_referenced_object(self, space):
        back_ref = self._read_int()
        chunk_index = 0
        chunk_offset = 0

        if space == AllocSpace.LO_SPACE:
            pass  # TODO
        elif space == AllocSpace.MAP_SPACE:
            pass  # TODO
        else:
            if self.is_32bit:
                chunk_index = (back_ref & 0x1FFE0000) >> 0x11
                chunk_offset = (back_ref & 0x1FFFF) << self.kObjectAlignmentBits
            else:
                chunk_index = (back_ref & 0x1FFF0000) >> 0x10
                chunk_offset = (back_ref & 0xFFFF) << self.kObjectAlignmentBits

        chunks = self.reserv.get(space, [])
        if chunk_index >= len(chunks):
            return None

        reserv_obj = chunks[chunk_index]
        back_obj = reserv_obj.get_aligned_object(chunk_offset)
        self.hots[self.last_hot_index] = back_obj
        self.last_hot_index = (self.last_hot_index + 1) & 7

        return back_obj

    def _get_maximum_fill_to_align(self):
        if self.next_alignment == AllocationAlignment.kWordAligned:
            return 0
        if self.next_alignment in (AllocationAlignment.kDoubleAligned, AllocationAlignment.kDoubleUnaligned):
            return 8 - self.kPointerSize
        return 0

    def _get_fill_to_align(self, address):
        if self.next_alignment == AllocationAlignment.kDoubleAligned and (address & 7) != 0:
            return self.kPointerSize
        if self.next_alignment == AllocationAlignment.kDoubleUnaligned and (address & 7) != 0:
            return 8 - self.kPointerSize
        return 0

    def _create_filler_object(self, obj, address, size):
        if size == 0:
            obj.add_object(address, None)
        elif size == self.kPointerSize:
            obj.add_object(address, self.roots[1] if len(self.roots) > 1 else None)
        elif size == 2 * self.kPointerSize:
            obj.add_object(address, self.roots[2] if len(self.roots) > 2 else None)
        else:
            obj.add_object(address, self.roots[0] if len(self.roots) > 0 else None)

    def _precede_with_filler(self, obj, address, size):
        self._create_filler_object(obj, address, size)
        return address + size

    def _align_with_filler(self, obj, address, object_size, filler_size):
        pre_filler = self._get_fill_to_align(address)
        if pre_filler != 0:
            address = self._precede_with_filler(obj, address, pre_filler)
            filler_size -= pre_filler
        if filler_size != 0:
            self._create_filler_object(obj, address + object_size, filler_size)

    def _read_object(self, obj, insert_off, space):
        size = self._read_int() << self.kObjectAlignmentBits

        space_chunk = self.last_chunk_index.get(space, 0)
        if self.next_alignment != AllocationAlignment.kWordAligned:
            chunks = self.reserv.get(space, [])
            if space_chunk < len(chunks):
                reserv_obj = chunks[space_chunk]
                address = reserv_obj.offset
                filler = self._get_maximum_fill_to_align()
                self._align_with_filler(reserv_obj, address, size, filler)
                reserv_obj.offset = address + filler
            self.next_alignment = AllocationAlignment.kWordAligned

        chunks = self.reserv.get(space, [])
        if space_chunk >= len(chunks):
            return

        reserv_obj = chunks[space_chunk]
        address = reserv_obj.offset
        reserv_obj.offset = address + size

        new_obj = ReservObject(size, self.kPointerSize)
        reserv_obj.add_object(address, new_obj)

        self._read_data(new_obj, size, space, 0)
        obj.add_object(insert_off, new_obj)

    def _read_int(self):
        answer = self.reader.read_uint32()
        bytes_count = (answer & 3) + 1
        self.reader.pos -= (4 - bytes_count)
        mask = 0xFFFFFFFF >> (32 - (bytes_count << 3))
        answer &= mask
        answer >>= 2
        return answer

    @staticmethod
    def _all_spaces(state):
        return AllocSpace.from_int(state.value - case_statement(state))

    @staticmethod
    def _new_space(state):
        return AllocSpace.from_int(state.value - case_statement(state)) == AllocSpace.NEW_SPACE
