from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

AES_BLOCK_128 = 0

#Import the python implementation of AddRoundKey for testing
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "third_party" / "boppreh-aes"))
import aes

@pytest.fixture
def lib():
    # Load the compiled shared library once and reuse it across tests.
    repo_root = Path(__file__).resolve().parent.parent
    lib = CDLL(str(repo_root / "rijndael.so"))

    lib.add_round_key.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_int]
    lib.add_round_key.restype = None

    return lib

def test_add_round_key_random(lib):
    for _ in range(3):  # Run the test 3 times with random inputs
        # Generate a random 16-byte input
        random_block = bytes([random.randint(0, 255) for _ in range(16)])
        random_key = bytes([random.randint(0, 255) for _ in range(16)])

        # Expected: XOR the block with the key
        expected = bytes(a ^ b for a, b in zip(random_block, random_key))

        buf_block = (c_ubyte * 16)(*random_block)
        buf_key = (c_ubyte * 16)(*random_key)
        lib.add_round_key(buf_block, buf_key, AES_BLOCK_128)
        # Assert that the output matches the expected output
        assert bytes(buf_block) == expected, f"Failed for input: {bytes(random_block)}"
