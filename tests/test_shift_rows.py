from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

AES_BLOCK_128 = 0

#Import the python implementation of ShiftRows for testing
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "third_party" / "boppreh-aes"))
import aes

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

def test_shift_rows_random(lib):
    for _ in range(3):  # Run the test 3 times with random inputs
        # Generate a random 16-byte input
        random_input = ([random.randint(0, 255) for _ in range(16)])

        # Compute the expected output from Python
        matrix = aes.bytes2matrix(random_input)
        aes.shift_rows(matrix)
        expected = aes.matrix2bytes(matrix)

    buf = (c_ubyte * 16)(*random_input)
    lib.shift_rows(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"

def test_invert_shift_rows_random(lib):
    for _ in range(3):  # Run the test 3 times with random inputs
        # Generate a random 16-byte input
        random_input = ([random.randint(0, 255) for _ in range(16)])

        # Compute the expected output from Python
        matrix = aes.bytes2matrix(random_input)
        aes.inv_shift_rows(matrix)
        expected = aes.matrix2bytes(matrix)

    buf = (c_ubyte * 16)(*random_input)
    lib.invert_shift_rows(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"