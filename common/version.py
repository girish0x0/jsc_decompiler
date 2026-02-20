import json
import os


def _mask32(v):
    return v & 0xFFFFFFFF


def _mask64(v):
    return v & 0xFFFFFFFFFFFFFFFF


def hash_value_unsigned(v):
    v = _mask32((v << 15) - v - 1)
    v = _mask32(v ^ (v >> 12))
    v = _mask32(v + (v << 2))
    v = _mask32(v ^ (v >> 4))
    v = _mask32(v * 2057)
    v = _mask32(v ^ (v >> 16))
    return v


def hash_combine(seed, value):
    value = _mask32(value * 0xCC9E2D51)
    value = _mask32((value >> 15) | (value << 17))
    value = _mask32(value * 0x1B873593)
    seed ^= value
    seed = _mask32((seed >> 13) | (seed << 19))
    seed = _mask32(seed * 5 + 0xE6546B64)
    return seed


def hash_combine64(seed, value):
    m = 0xC6A4A7935BD1E995
    value = _mask64(value * m)
    value = _mask64(value ^ (value >> 47))
    value = _mask64(value * m)
    seed = _mask64(seed ^ value)
    seed = _mask64(seed * m)
    return seed


def version_hash(major, minor, build, patch):
    seed = 0
    seed = hash_combine(seed, hash_value_unsigned(patch))
    seed = hash_combine(seed, hash_value_unsigned(build))
    seed = hash_combine(seed, hash_value_unsigned(minor))
    seed = hash_combine(seed, hash_value_unsigned(major))
    return seed


def version_hash64(major, minor, build, patch):
    seed = 0
    seed = hash_combine64(seed, hash_value_unsigned(patch))
    seed = hash_combine64(seed, hash_value_unsigned(build))
    seed = hash_combine64(seed, hash_value_unsigned(minor))
    seed = hash_combine64(seed, hash_value_unsigned(major))
    return _mask32(seed)


class V8VersionDetector:
    def __init__(self, data_dir=None):
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

        self.ver_hashes_32 = {}
        self.ver_hashes_64 = {}

        versions_file = os.path.join(data_dir, "v8_versions.json")
        with open(versions_file, "r") as f:
            versions = json.load(f)

        for ver in versions:
            parts = ver.split(".")
            if len(parts) != 4:
                continue

            major, minor, build, patch = (int(p) for p in parts)

            h32 = version_hash(major, minor, build, patch)
            h64 = version_hash64(major, minor, build, patch)

            self.ver_hashes_32[h32] = ver
            self.ver_hashes_64[h64] = ver

    def detect_version(self, hash_val):
        ver = self.ver_hashes_32.get(hash_val)
        if ver is not None:
            return ver

        ver = self.ver_hashes_64.get(hash_val)
        if ver is not None:
            return ver

        return "Unknown"

    def detect_bitness(self, hash_val):
        if hash_val in self.ver_hashes_32:
            return True  # is 32-bit
        if hash_val in self.ver_hashes_64:
            return False  # is 64-bit
        raise ValueError("Unknown bitness for hash 0x%08X" % hash_val)
