# DES Encryption and Decryption Project

**Author:** Rhiannon Barber  
**Course:** CS454 - Homework 1  
**Date:** October 20, 2025  

This project implements the Data Encryption Standard (DES) algorithm in Python.  
The program can perform both encryption and decryption on 64-bit data blocks using a 64-bit key.  
It is designed to follow the format and output structure of the sample files provided in the homework instructions.

---

## Purpose

The purpose of this project is to demonstrate an understanding of the DES encryption algorithm by implementing it from scratch in Python.  
The program replicates each step of DES, including key generation, initial and inverse permutations, S-box substitutions, and the 16 Feistel rounds.  
The final output matches, and is verified by showing all intermediate round values and the resulting ciphertext or plaintext.

---

## Repository Contents
DES.py # Main DES implementation
des_tables.py # Contains DES permutation and substitution tables
test_des_unit.py # Unit tests for core functions
test_des_integration.py # Integration tests simulating full runs
requirements.txt # Python dependencies (pytest)
.github/workflows/
└── python-tests.yml # GitHub Actions workflow for automated testing

---

## How to Run the Program
The program takes a single input file formatted as:

```
data_block: 0123456789ABCDEF
key: 133457799BBCDFF1
operation: encryption
```

To run the program, use:

```
python3 DES.py <your_input_file.txt>
```

The output file will be created automatically:
- `program_results_output_encryption.txt` for encryption
- `program_results_output_decryption.txt` for decryption

Each output file lists the intermediate results for all DES rounds and ends with a line showing the final result, such as:
```
Result = 85E813540F0AB405
```
## Testing

This project includes automated unit and integrated tests written with the pytest framework.  
They verify the correct functionality of both individual components of the DES implementation, and the full encryption/decryption process.

The project uses a GitHub workflow to run the testing suite for full automation. 

**This project was tested with the files 'testing_input_dec.txt' and 'testing_input_enc.txt' to verify that the program can work with other files than the given files for the assignment.** 

