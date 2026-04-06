from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

AES_BLOCK_128 = 0
AES_BLOCK_256 = 1
AES_BLOCK_512 = 2

# Known AES ShiftRows test vector:
SHIFT_ROWS_IN_128 = bytes(range(16))
SHIFT_ROWS_OUT_128 = bytes([
    0X00, 0X05, 0X0A, 0X0F, #Row 0: no shift
    0X04, 0X09, 0X0E, 0X03, #Row 1: shift left by 1
    0X08, 0X0D, 0X02, 0X07, #Row 2: shift left by 2
    0X0C, 0X01, 0X06, 0X0B, #Row 3: shift left by 3
])

SHIFT_ROWS_IN_256 = bytes(range(32))
SHIFT_ROWS_IN_512 = bytes(range(64))

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
    
def test_shift_rows_128(lib):
    buf = (c_ubyte * len(SHIFT_ROWS_IN_128))(*SHIFT_ROWS_IN_128)     # mutable c_ubyte array initialized from bytes
    lib.shift_rows(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == SHIFT_ROWS_OUT_128

def test_invert_shift_rows_128(lib):
    buf = (c_ubyte * len(SHIFT_ROWS_OUT_128))(*SHIFT_ROWS_OUT_128)
    lib.invert_shift_rows(buf, AES_BLOCK_128)
    # Assert that the output matches the expected output
    assert bytes(buf) == SHIFT_ROWS_IN_128

def test_shift_rows_256(lib):
    buf = (c_ubyte * len(SHIFT_ROWS_IN_256))(*SHIFT_ROWS_IN_256)
    lib.shift_rows(buf, AES_BLOCK_256)
    shifted = bytes(buf)
    
    # Round-trip test: shift then invert_shift should get original back
    buf2 = (c_ubyte * len(shifted))(*shifted)
    lib.invert_shift_rows(buf2, AES_BLOCK_256)
    assert bytes(buf2) == SHIFT_ROWS_IN_256

def test_shift_rows_512(lib):
    buf = (c_ubyte * len(SHIFT_ROWS_IN_512))(*SHIFT_ROWS_IN_512)
    lib.shift_rows(buf, AES_BLOCK_512)
    shifted = bytes(buf)
    
    # Round-trip test
    buf2 = (c_ubyte * len(shifted))(*shifted)
    lib.invert_shift_rows(buf2, AES_BLOCK_512)
    assert bytes(buf2) == SHIFT_ROWS_IN_512

def test_shift_rows_random_all_sizes(lib):
    for block_size, enum_val, block_bytes in [(128, AES_BLOCK_128, 16), (256, AES_BLOCK_256, 32), (512, AES_BLOCK_512, 64)]:
        for _ in range(3):  # Run the test 3 times with random inputs
            # Generate a random {block_bytes}-byte input
            random_input = ([random.randint(0, 255) for _ in range(block_bytes)])

            if block_size == 128:
                # For 128-bit, use Python reference
                matrix = aes.bytes2matrix(random_input)
                aes.shift_rows(matrix)
                expected = aes.matrix2bytes(matrix)

                buf = (c_ubyte * block_bytes)(*random_input)
                lib.shift_rows(buf, enum_val)
                assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"
            else:
                # For 256/512, use round-trip
                buf = (c_ubyte * block_bytes)(*random_input)
                lib.shift_rows(buf, enum_val)
                shifted = bytes(buf)
                
                buf2 = (c_ubyte * block_bytes)(*shifted)
                lib.invert_shift_rows(buf2, enum_val)
                assert bytes(buf2) == bytes(random_input), f"Round-trip failed for {block_size}-bit block"

def test_invert_shift_rows_random_all_sizes(lib):
    for block_size, enum_val, block_bytes in [(128, AES_BLOCK_128, 16), (256, AES_BLOCK_256, 32), (512, AES_BLOCK_512, 64)]:
        for _ in range(3):  # Run the test 3 times with random inputs
            # Generate a random {block_bytes}-byte input
            random_input = ([random.randint(0, 255) for _ in range(block_bytes)])

            if block_size == 128:
                # For 128-bit, use Python reference
                matrix = aes.bytes2matrix(random_input)
                aes.inv_shift_rows(matrix)
                expected = aes.matrix2bytes(matrix)

                buf = (c_ubyte * block_bytes)(*random_input)
                lib.invert_shift_rows(buf, enum_val)
                assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"
            else:
                # For 256/512, use round-trip
                buf = (c_ubyte * block_bytes)(*random_input)
                lib.invert_shift_rows(buf, enum_val)
                inv_shifted = bytes(buf)
                
                buf2 = (c_ubyte * block_bytes)(*inv_shifted)
                lib.shift_rows(buf2, enum_val)
                assert bytes(buf2) == bytes(random_input), f"Round-trip failed for {block_size}-bit block"