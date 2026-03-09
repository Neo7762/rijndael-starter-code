from pathlib import Path
from ctypes import CDLL

import pytest

def test_smoke():
    repo_root = Path(__file__).resolve().parent.parent
    so_file = repo_root / "rijndael.so"
    assert so_file.is_file(), "The file rijndael.so does not exist in the given directory."

    try:
        lib = CDLL(str(so_file))
    except OSError as e:
        pytest.fail(f"Failed to load the shared library: {e}")
    
    assert hasattr(lib, "aes_encrypt_block"), "The function 'aes_encrypt_block' is not found in the shared library"
    assert hasattr(lib, "aes_decrypt_block"), "The function 'aes_decrypt_block' is not found in the shared library"