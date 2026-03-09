from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest

AES_BLOCK_128 = 0

# Known AES SubBytes test vector:
# applying SubBytes to bytes 0x00..0x0F should produce SUB_OUT.
SUB_IN = bytes(range(16))
SUB_OUT = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
])

@pytest.fixture
def lib():
    # Load the compiled shared library once and reuse it across tests.
    repo_root = Path(__file__).resolve().parent.parent
    lib = CDLL(str(repo_root / "rijndael.so"))

    lib.sub_bytes.argtypes = [POINTER(c_ubyte), c_int]
    lib.sub_bytes.restype = None

    lib.invert_sub_bytes.argtypes = [POINTER(c_ubyte), c_int]
    lib.invert_sub_bytes.restype = None

    return lib

def test_sub_bytes(lib):
    buf = (c_ubyte * len(SUB_IN))(*SUB_IN)     # mutable c_ubyte array initialized from bytes
    lib.sub_bytes(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == SUB_OUT

def test_invert_sub_bytes(lib):
    buf = (c_ubyte * len(SUB_OUT))(*SUB_OUT)
    lib.invert_sub_bytes(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == SUB_IN