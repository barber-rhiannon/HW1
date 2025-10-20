'''
Author: Rhiannon Barber
Date: Oct. 20, 2025
CS454: Homework 1 - DES project

Integration tests:
- test_cli_encryption_standard_vector: CLI encryption writes correct result and sections
- test_cli_decryption_standard_vector: CLI decryption writes correct result and sections
- test_cli_handles_lowercase_and_whitespace: CLI normalizes lowercase hex and extra spaces
- test_cli_creates_distinct_output_files: encryption and decryption produce separate files
- test_cli_missing_argument: running without args exits nonzero and prints usage
'''

import os
import re
import subprocess
from pathlib import Path


def write_input_file(path: Path, data_hex: str, key_hex: str, operation: str):
    path.write_text(
        f"data_block: {data_hex}\n"
        f"key: {key_hex}\n"
        f"operation: {operation}\n"
    )


def run_script(input_path: Path):
    return subprocess.run(
        ["python3", "DES.py", str(input_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def read_result_file(path: Path):
    assert path.exists()
    text = path.read_text().strip()
    m = re.search(r"Result=([0-9A-F]{16})$", text, re.M)
    assert m
    return m.group(1), text


def test_cli_encryption_standard_vector(tmp_path: Path):
    data = "0123456789ABCDEF"
    key = "133457799BBCDFF1"
    input_file = tmp_path / "enc.txt"
    write_input_file(input_file, data, key, "encryption")
    cp = run_script(input_file)
    assert cp.returncode == 0
    out_file = Path("program_results_output_encryption.txt")
    result_hex, contents = read_result_file(out_file)
    assert result_hex == "85E813540F0AB405"
    assert "C0=" in contents and "D0=" in contents
    assert "K16=" in contents
    assert "L16=" in contents and "R16=" in contents


def test_cli_decryption_standard_vector(tmp_path: Path):
    data = "85E813540F0AB405"
    key = "133457799BBCDFF1"
    input_file = tmp_path / "dec.txt"
    write_input_file(input_file, data, key, "decryption")
    cp = run_script(input_file)
    assert cp.returncode == 0
    out_file = Path("program_results_output_decryption.txt")
    result_hex, contents = read_result_file(out_file)
    assert result_hex == "0123456789ABCDEF"
    assert "C0=" in contents and "D0=" in contents
    assert "K1=" in contents and "K16=" in contents
    assert "L0=" in contents and "R0=" in contents


def test_cli_handles_lowercase_and_whitespace(tmp_path: Path):
    data = "0123456789abcdef"
    key = "133457799bbcdff1"
    input_file = tmp_path / "messy.txt"
    input_file.write_text(
        "data_block:   " + data + "   \n"
        "key:   " + key + "   \n"
        "operation:   encryption   \n"
    )
    cp = run_script(input_file)
    assert cp.returncode == 0
    out_file = Path("program_results_output_encryption.txt")
    result_hex, _ = read_result_file(out_file)
    assert result_hex == "85E813540F0AB405"


def test_cli_creates_distinct_output_files(tmp_path: Path):
    data = "0123456789ABCDEF"
    key = "133457799BBCDFF1"
    enc_in = tmp_path / "enc.txt"
    dec_in = tmp_path / "dec.txt"
    write_input_file(enc_in, data, key, "encryption")
    write_input_file(dec_in, "85E813540F0AB405", key, "decryption")
    rc1 = run_script(enc_in).returncode
    rc2 = run_script(dec_in).returncode
    assert rc1 == 0 and rc2 == 0
    enc_file = Path("program_results_output_encryption.txt")
    dec_file = Path("program_results_output_decryption.txt")
    assert enc_file.exists() and dec_file.exists()
    enc_result, _ = read_result_file(enc_file)
    dec_result, _ = read_result_file(dec_file)
    assert enc_result == "85E813540F0AB405"
    assert dec_result == "0123456789ABCDEF"


def test_cli_missing_argument():
    cp = subprocess.run(
        ["python3", "DES.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert cp.returncode != 0
    assert "python3 DES.py" in (cp.stdout + cp.stderr)
