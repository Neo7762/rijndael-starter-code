from pathlib import Path
from ctypes import CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

AES_BLOCK_128 = 0
AES_BLOCK_256 = 1
AES_BLOCK_512 = 2

# Known AES MixColumns test vector (128-bit):
# applying MixColumns to bytes 0x00..0x0F should produce MIX_COLUMNS_OUT.
MIX_COLUMNS_IN_128 = bytes(range(16))
MIX_COLUMNS_OUT_128 = bytes([
    0x02, 0x07, 0x00, 0x05, 
    0x06, 0x03, 0x04, 0x01,
    0x0a, 0x0f, 0x08, 0x0d,
    0x0e, 0x0b, 0x0c, 0x09
])

MIX_COLUMNS_IN_256 = bytes(range(32))
MIX_COLUMNS_IN_512 = bytes(range(64))

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

def test_mix_columns_128(lib):
    buf = (c_ubyte * len(MIX_COLUMNS_IN_128))(*MIX_COLUMNS_IN_128)
    lib.mix_columns(buf, AES_BLOCK_128)
    assert bytes(buf) == MIX_COLUMNS_OUT_128

def test_invert_mix_columns_128(lib):
    buf = (c_ubyte * len(MIX_COLUMNS_OUT_128))(*MIX_COLUMNS_OUT_128)
    lib.invert_mix_columns(buf, AES_BLOCK_128)
    assert bytes(buf) == MIX_COLUMNS_IN_128

def test_mix_columns_256(lib):
    buf = (c_ubyte * len(MIX_COLUMNS_IN_256))(*MIX_COLUMNS_IN_256)
    lib.mix_columns(buf, AES_BLOCK_256)
    shifted = bytes(buf)
    
    # Round-trip test: mix then invert_mix should get original back
    buf2 = (c_ubyte * len(shifted))(*shifted)
    lib.invert_mix_columns(buf2, AES_BLOCK_256)
    assert bytes(buf2) == MIX_COLUMNS_IN_256

def test_mix_columns_512(lib):
    buf = (c_ubyte * len(MIX_COLUMNS_IN_512))(*MIX_COLUMNS_IN_512)
    lib.mix_columns(buf, AES_BLOCK_512)
    mixed = bytes(buf)
    
    # Round-trip test
    buf2 = (c_ubyte * len(mixed))(*mixed)
    lib.invert_mix_columns(buf2, AES_BLOCK_512)
    assert bytes(buf2) == MIX_COLUMNS_IN_512

def test_mix_columns_random_all_sizes(lib):
    for block_size, enum_val, block_bytes in [(128, AES_BLOCK_128, 16), (256, AES_BLOCK_256, 32), (512, AES_BLOCK_512, 64)]:
        for _ in range(3):  # Run the test 3 times with random inputs
            # Generate a random {block_bytes}-byte input
            random_input = [random.randint(0, 255) for _ in range(block_bytes)]

            if block_size == 128:
                # For 128-bit, use Python reference
                matrix = aes.bytes2matrix(random_input)
                aes.mix_columns(matrix)
                expected = aes.matrix2bytes(matrix)

                buf = (c_ubyte * block_bytes)(*random_input)
                lib.mix_columns(buf, enum_val)
                assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"
            else:
                # For 256/512, use round-trip
                buf = (c_ubyte * block_bytes)(*random_input)
                lib.mix_columns(buf, enum_val)
                mixed = bytes(buf)
                
                buf2 = (c_ubyte * block_bytes)(*mixed)
                lib.invert_mix_columns(buf2, enum_val)
                assert bytes(buf2) == bytes(random_input), f"Round-trip failed for {block_size}-bit block"

def test_invert_mix_columns_random_all_sizes(lib):
    for block_size, enum_val, block_bytes in [(128, AES_BLOCK_128, 16), (256, AES_BLOCK_256, 32), (512, AES_BLOCK_512, 64)]:
        for _ in range(3):  # Run the test 3 times with random inputs
            # Generate a random {block_bytes}-byte input
            random_input = [random.randint(0, 255) for _ in range(block_bytes)]

            if block_size == 128:
                # For 128-bit, use Python reference
                matrix = aes.bytes2matrix(random_input)
                aes.inv_mix_columns(matrix)
                expected = aes.matrix2bytes(matrix)

                buf = (c_ubyte * block_bytes)(*random_input)
                lib.invert_mix_columns(buf, enum_val)
                assert bytes(buf) == expected, f"Failed for input: {bytes(random_input)}"
            else:
                # For 256/512, use round-trip
                buf = (c_ubyte * block_bytes)(*random_input)
                lib.invert_mix_columns(buf, enum_val)
                inv_mixed = bytes(buf)
                
                buf2 = (c_ubyte * block_bytes)(*inv_mixed)
                lib.mix_columns(buf2, enum_val)
                assert bytes(buf2) == bytes(random_input), f"Round-trip failed for {block_size}-bit block"