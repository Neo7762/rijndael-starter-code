from pathlib import Path
from ctypes import cast, CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

AES_BLOCK_128 = 0

#Import the python implementation of ExpandKey for testing
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "third_party" / "boppreh-aes"))
import aes

@pytest.fixture
def lib():
    # Load the compiled shared library once and reuse it across tests.
    repo_root = Path(__file__).resolve().parent.parent
    lib = CDLL(str(repo_root / "rijndael.so"))

    lib.expand_key.argtypes = [POINTER(c_ubyte), c_int]
    lib.expand_key.restype = POINTER(c_ubyte)

    return lib

def test_expand_key_random(lib):
    for _ in range(3):  # Run the test 3 times with random inputs
        # Generate a random 16-byte input
        random_key = bytes([random.randint(0, 255) for _ in range(16)])

        # Get expected output from Python
        aes_instance = aes.AES(random_key)
        expected_round_keys = aes_instance._key_matrices # This is the expanded key schedule
        expected_bytes = b''.join(bytes(word) for matrix in expected_round_keys for word in matrix)


        #Test C implementation
        #Assuming expand_key returns a pointer to 176 bytes (11 round keys of 16 bytes each for AES-128)
        expanded = lib.expand_key((c_ubyte * 16)(*random_key), AES_BLOCK_128)
        result = bytes(cast(expanded, POINTER(c_ubyte * 176)).contents)

        # Assert that the output matches the expected output
        assert result == expected_bytes, f"Failed for input: {random_key}"