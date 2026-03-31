from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest

AES_BLOCK_128 = 0

# Known AES MixColumns test vector:
# applying MixColumns to bytes 0x00..0x0F should produce MIX_COLUMNS_OUT.
MIX_COLUMNS_IN = bytes(range(16))
MIX_COLUMNS_OUT = bytes([
    0x02, 0x07, 0x00, 0x05, 
    0x06, 0x03, 0x04, 0x01,
    0x0a, 0x0f, 0x08, 0x0d,
    0x0e, 0x0b, 0x0c, 0x09
])

@pytest.fixture
def lib():
    # Load the compiled shared library once and reuse it across tests.
    repo_root = Path(__file__).resolve().parent.parent
    lib = CDLL(str(repo_root / "rijndael.so"))

    lib.mix_columns.argtypes = [POINTER(c_ubyte), c_int]
    lib.mix_columns.restype = None

    lib.invert_mix_columns.argtypes = [POINTER(c_ubyte), c_int]
    lib.invert_mix_columns.restype = None

    return lib

def test_mix_columns(lib):
    buf = (c_ubyte * len(MIX_COLUMNS_IN))(*MIX_COLUMNS_IN)     # mutable c_ubyte array initialized from bytes
    lib.mix_columns(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == MIX_COLUMNS_OUT

def test_invert_mix_columns(lib):
    buf = (c_ubyte * len(MIX_COLUMNS_OUT))(*MIX_COLUMNS_OUT)
    lib.invert_mix_columns(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == MIX_COLUMNS_IN