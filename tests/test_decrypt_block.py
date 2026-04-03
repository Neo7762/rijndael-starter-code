from pathlib import Path
from ctypes import cast, CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

AES_BLOCK_128 = 0

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "third_party" / "boppreh-aes"))
import aes

@pytest.fixture
def lib():
    repo_root = Path(__file__).resolve().parent.parent
    lib = CDLL(str(repo_root / "rijndael.so"))

    lib.aes_decrypt_block.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_int]
    lib.aes_decrypt_block.restype = POINTER(c_ubyte)

    return lib

def test_aes_decryption_block_known(lib):
    # Use a simple known test vector
    ciphertext = bytes([0x00] * 16)  # All zeros
    key = bytes([0x00] * 16)  # All zeros
    
    # Expected output from Python
    aes_instance = aes.AES(key)
    expected = aes_instance.decrypt_block(ciphertext)
    
    # Test C implementation
    buf_plain = (c_ubyte * 16)(*ciphertext)
    buf_key = (c_ubyte * 16)(*key)
    decrypted = lib.aes_decrypt_block(buf_plain, buf_key, AES_BLOCK_128)
    result = bytes(cast(decrypted, POINTER(c_ubyte * 16)).contents)
    
    print(f"Expected: {expected.hex()}")
    print(f"Got:      {result.hex()}")
    assert result == expected

def test_aes_decrypt_block_random(lib):
    for _ in range(3):  # Run the test 3 times with random inputs
        ciphertext = bytes(random.randint(0, 255) for _ in range(16))
        key = bytes(random.randint(0, 255) for _ in range(16))
        
        # Expected output from Python
        aes_instance = aes.AES(key)
        expected = aes_instance.decrypt_block(ciphertext)
        
        # Test C implementation
        buf_plain = (c_ubyte * 16)(*ciphertext)
        buf_key = (c_ubyte * 16)(*key)
        decrypted = lib.aes_decrypt_block(buf_plain, buf_key, AES_BLOCK_128)
        result = bytes(cast(decrypted, POINTER(c_ubyte * 16)).contents)
        
        assert result == expected, f"Failed for ciphertext: {ciphertext.hex()}, key: {key.hex()}"