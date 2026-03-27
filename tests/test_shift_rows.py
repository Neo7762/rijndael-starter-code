from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest

AES_BLOCK_128 = 0

# Known AES ShiftRows test vector:
# applying ShiftRows to bytes 0x00..0x0F should produce SHIFT_ROWS_OUT.
SHIFT_ROWS_IN = bytes(range(16))
SHIFT_ROWS_OUT = bytes([
    0X00, 0X05, 0X0A, 0X0F, #Row 0: no shift
    0X04, 0X09, 0X0E, 0X03, #Row 1: shift left by 1
    0X08, 0X0D, 0X02, 0X07, #Row 2: shift left by 2
    0X0C, 0X01, 0X06, 0X0B, #Row 3: shift left by 3
])

@pytest.fixture
def lib():
    # Load the compiled shared library once and reuse it across tests.
    repo_root = Path(__file__).resolve().parent.parent
    lib = CDLL(str(repo_root / "rijndael.so"))

    lib.shift_rows.argtypes = [POINTER(c_ubyte), c_int]
    lib.shift_rows.restype = None

    lib.invert_shift_rows.argtypes = [POINTER(c_ubyte), c_int]
    lib.invert_shift_rows.restype = None

    return lib

def test_shift_rows(lib):
    buf = (c_ubyte * len(SHIFT_ROWS_IN))(*SHIFT_ROWS_IN)     # mutable c_ubyte array initialized from bytes
    lib.shift_rows(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == SHIFT_ROWS_OUT

def test_invert_shift_rows(lib):
    buf = (c_ubyte * len(SHIFT_ROWS_OUT))(*SHIFT_ROWS_OUT)
    lib.invert_shift_rows(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == SHIFT_ROWS_IN