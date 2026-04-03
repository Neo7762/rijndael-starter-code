from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

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

#Import the python implementation of MixColumns for testing
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "third_party" / "boppreh-aes"))
import aes

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

def test_mix_columns_random(lib):
    for _ in range(3):  # Run the test 3 times with random inputs
        # Generate a random 16-byte input
        random_input = ([random.randint(0, 255) for _ in range(16)])

        # Compute the expected output from Python
        matrix = aes.bytes2matrix(random_input)
        aes.mix_columns(matrix)
        expected = aes.matrix2bytes(matrix)

        buf = (c_ubyte * 16)(*random_input)
        lib.mix_columns(buf, AES_BLOCK_128)
        # Assert that the output matches the expected output
        assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"

def test_invert_mix_columns_random(lib):
    for _ in range(3):  # Run the test 3 times with random inputs
        # Generate a random 16-byte input
        random_input = ([random.randint(0, 255) for _ in range(16)])

        # Compute the expected output from Python
        matrix = aes.bytes2matrix(random_input)
        aes.inv_mix_columns(matrix)
        expected = aes.matrix2bytes(matrix)

        buf = (c_ubyte * 16)(*random_input)
        lib.invert_mix_columns(buf, AES_BLOCK_128)
        # Assert that the output matches the expected output
        assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"