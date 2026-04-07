# tests/test_decrypt_block.py
from pathlib import Path
from ctypes import cast, CDLL, c_ubyte, POINTER, c_int
import pytest
import random
import sys

AES_BLOCK_128 = 0
AES_BLOCK_256 = 1
AES_BLOCK_512 = 2

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "third_party" / "boppreh-aes"))
import aes

@pytest.fixture
def lib():
    repo_root = Path(__file__).resolve().parent.parent
    lib = CDLL(str(repo_root / "rijndael.so"))

    lib.aes_decrypt_block.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_int]
    lib.aes_decrypt_block.restype = POINTER(c_ubyte)
    
    lib.aes_encrypt_block.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_int]
    lib.aes_encrypt_block.restype = POINTER(c_ubyte)

    return lib

def test_aes_decrypt_block_known_128(lib):
    ciphertext = bytes([0x00] * 16)
    key = bytes([0x00] * 16)
    
    aes_instance = aes.AES(key)
    expected = aes_instance.decrypt_block(ciphertext)
    
    buf_plain = (c_ubyte * 16)(*ciphertext)
    buf_key = (c_ubyte * 16)(*key)
    decrypted = lib.aes_decrypt_block(buf_plain, buf_key, AES_BLOCK_128)
    result = bytes(cast(decrypted, POINTER(c_ubyte * 16)).contents)
    
    print(f"Expected: {expected.hex()}")
    print(f"Got:      {result.hex()}")
    assert result == expected

def test_aes_decrypt_block_random_128(lib):
    for _ in range(3):
        ciphertext = bytes(random.randint(0, 255) for _ in range(16))
        key = bytes(random.randint(0, 255) for _ in range(16))
        
        aes_instance = aes.AES(key)
        expected = aes_instance.decrypt_block(ciphertext)
        
        buf_plain = (c_ubyte * 16)(*ciphertext)
        buf_key = (c_ubyte * 16)(*key)
        decrypted = lib.aes_decrypt_block(buf_plain, buf_key, AES_BLOCK_128)
        result = bytes(cast(decrypted, POINTER(c_ubyte * 16)).contents)
        
        assert result == expected, f"Failed for ciphertext: {ciphertext.hex()}, key: {key.hex()}"

def test_aes_decrypt_block_known_256(lib):
    plaintext = bytes([0x00] * 32)
    key = bytes([0x00] * 16)
    
    # Encrypt first
    buf_plain = (c_ubyte * 32)(*plaintext)
    buf_key = (c_ubyte * 16)(*key)
    encrypted = lib.aes_encrypt_block(buf_plain, buf_key, AES_BLOCK_256)
    
    # Then decrypt and verify
    decrypted = lib.aes_decrypt_block(encrypted, buf_key, AES_BLOCK_256)
    result = bytes(cast(decrypted, POINTER(c_ubyte * 32)).contents)
    
    assert result == plaintext

def test_aes_decrypt_block_random_256(lib):
    for _ in range(3):
        plaintext = bytes(random.randint(0, 255) for _ in range(32))
        key = bytes(random.randint(0, 255) for _ in range(16))
        
        # Encrypt
        buf_plain = (c_ubyte * 32)(*plaintext)
        buf_key = (c_ubyte * 16)(*key)
        encrypted = lib.aes_encrypt_block(buf_plain, buf_key, AES_BLOCK_256)
        
        # Decrypt
        decrypted = lib.aes_decrypt_block(encrypted, buf_key, AES_BLOCK_256)
        result = bytes(cast(decrypted, POINTER(c_ubyte * 32)).contents)
        
        assert result == plaintext, f"Failed for 256-bit block"

def test_aes_decrypt_block_known_512(lib):
    plaintext = bytes([0x00] * 64)
    key = bytes([0x00] * 16)
    
    # Encrypt first
    buf_plain = (c_ubyte * 64)(*plaintext)
    buf_key = (c_ubyte * 16)(*key)
    encrypted = lib.aes_encrypt_block(buf_plain, buf_key, AES_BLOCK_512)
    
    # Then decrypt and verify
    decrypted = lib.aes_decrypt_block(encrypted, buf_key, AES_BLOCK_512)
    result = bytes(cast(decrypted, POINTER(c_ubyte * 64)).contents)
    
    assert result == plaintext

def test_aes_decrypt_block_random_512(lib):
    for _ in range(3):
        plaintext = bytes(random.randint(0, 255) for _ in range(64))
        key = bytes(random.randint(0, 255) for _ in range(16))
        
        # Encrypt
        buf_plain = (c_ubyte * 64)(*plaintext)
        buf_key = (c_ubyte * 16)(*key)
        encrypted = lib.aes_encrypt_block(buf_plain, buf_key, AES_BLOCK_512)
        
        # Decrypt
        decrypted = lib.aes_decrypt_block(encrypted, buf_key, AES_BLOCK_512)
        result = bytes(cast(decrypted, POINTER(c_ubyte * 64)).contents)
        
        assert result == plaintext, f"Failed for 512-bit block"