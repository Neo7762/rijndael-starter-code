from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

AES_BLOCK_128 = 0
AES_BLOCK_256 = 1
AES_BLOCK_512 = 2

# Known AES SubBytes test vector:
SUB_IN_128 = bytes(range(16))
SUB_OUT_128 = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
])
SUB_IN_256 = bytes(range(32))
SUB_IN_512 = bytes(range(64))

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

def test_sub_bytes_128(lib):
    buf = (c_ubyte * len(SUB_IN_128))(*SUB_IN_128)
    lib.sub_bytes(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == SUB_OUT_128

def test_invert_sub_bytes_128(lib):
    buf = (c_ubyte * len(SUB_OUT_128))(*SUB_OUT_128)
    lib.invert_sub_bytes(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == SUB_IN_128

def test_sub_bytes_256(lib):
    buf = (c_ubyte * len(SUB_IN_256))(*SUB_IN_256)
    lib.sub_bytes(buf, AES_BLOCK_256)
    expected = bytes([aes.s_box[byte] for byte in SUB_IN_256])
    assert bytes(buf) == expected

def test_sub_bytes_512(lib):
    buf = (c_ubyte * len(SUB_IN_512))(*SUB_IN_512)
    lib.sub_bytes(buf, AES_BLOCK_512)
    expected = bytes([aes.s_box[byte] for byte in SUB_IN_512])
    assert bytes(buf) == expected

def test_sub_bytes_random_all_sizes(lib):
    for block_size, enum_val, block_bytes in [(128, AES_BLOCK_128, 16), (256, AES_BLOCK_256, 32), (512, AES_BLOCK_512, 64)]:
        for _ in range(3):  # Run the test 3 times with random inputs
            # Generate a random {block_bytes}-byte input
            random_input = ([random.randint(0, 255) for _ in range(block_bytes)])

            # Compute the expected output from Python
            expected = bytes([aes.s_box[byte] for byte in random_input])
        
            buf = (c_ubyte * block_bytes)(*random_input)
            lib.sub_bytes(buf, enum_val)
            # Assert that the output matches the expected output
            assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"

def test_invert_sub_bytes_random_all_sizes(lib):
    for block_size, enum_val, block_bytes in [(128, AES_BLOCK_128, 16), (256, AES_BLOCK_256, 32), (512, AES_BLOCK_512, 64)]:
        for _ in range(3):  # Run the test 3 times with random inputs
            # Generate a random {block_bytes}-byte input
            random_input = ([random.randint(0, 255) for _ in range(block_bytes)])

            # Compute the expected output from Python
            expected = bytes([aes.inv_s_box[byte] for byte in random_input])

            buf = (c_ubyte * block_bytes)(*random_input)
            lib.invert_sub_bytes(buf, enum_val)
            # Assert that the output matches the expected output
            assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"