from pathlib import Path

def test_smoke():
    repo_root = Path(__file__).resolve().parent.parent
    so_file = repo_root / "rijndael.so"
    assert so_file.is_file(), "The file rijndael.so does not exist in the given directory."