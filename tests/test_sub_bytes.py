from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

AES_BLOCK_128 = 0

#Import the sbox and inv_sbox from the shared library for testing
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "third_party" / "boppreh-aes"))
import aes

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

def test_sub_bytes_random(lib):
    for _ in range(3):  # Run the test 3 times with random inputs
        # Generate a random 16-byte input
        random_input = ([random.randint(0, 255) for _ in range(16)])

        # Compute the expected output from Python
        expected = bytes([aes.s_box[byte] for byte in random_input])
        
        buf = (c_ubyte * 16)(*random_input)
        lib.sub_bytes(buf, AES_BLOCK_128)
        # Assert that the output matches the expected output
        assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"

def test_invert_sub_bytes_random(lib):
    for _ in range(3):  # Run the test 3 times with random inputs
        # Generate a random 16-byte input
        random_input = ([random.randint(0, 255) for _ in range(16)])

        # Compute the expected output from Python
        expected = bytes([aes.inv_s_box[byte] for byte in random_input])

        buf = (c_ubyte * 16)(*random_input)
        lib.invert_sub_bytes(buf, AES_BLOCK_128)
        # Assert that the output matches the expected output
        assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"