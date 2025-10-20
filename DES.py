#!/usr/bin/env python3

'''
Author: Rhiannon Barber
Date: Oct. 20, 2025
CS454: Homework 1 - DES project

This program is written in Python programming language, using the PyCharm IDE.
This file contains the implementation for the DES process used with any input files that follow the format
of the sample given.

TO RUN THIS PROGRAM:
python3 DES.py <your_input_file_encryption.txt> : This command runs the encryption operation.
python3 DES.py <your_input_file_decryption.txt> : This command runs the decryption operation.

The results will be found in ' program_results_output_decryption.txt OR program_results_output_encryption.txt '
                               depending on the operation selected.
'''

import sys
import time
from des_tables import INITIAL_PERMUTATION, INVERSE_INITIAL_PERMUTATION, EXPANSION_TABLE, PBOX_PERMUTATION, PERMUTATION_CHOICE_1, PERMUTATION_CHOICE_2, KEY_SHIFTS_PER_ROUND, SBOXES


'''
Converts a hexadecimal string to a binary string of a given length.
Input: h (hex string), b (bit length)
Output: binary string of length b
Purpose: Used throughout DES to represent data and keys in binary form.
'''
def hex_to_binary(h, b):
    return bin(int(h, 16))[2:].zfill(b)

'''
Applies a given permutation table to a binary string.
Input: bits (binary string), table (list of integer indices)
Output: permuted binary string
Purpose: Used for IP, IP⁻¹, PC1, PC2, and other permutation steps in DES.
'''

def binary_to_hex(b):
    return hex(int(b, 2))[2:].upper().zfill(16)


'''
Applies a given permutation table to a binary string.
Input: bits (binary string), table (list of integer indices)
Output: permuted binary string
Purpose: Used for IP, IP⁻¹, PC1, PC2, and other permutation steps in DES.
'''
def apply_permutation(bits, table):
    return ''.join(bits[i - 1] for i in table)

'''
Performs a circular left rotation on a binary string.
Input: bits (binary string), n (integer shift amount)
Output: rotated binary string
Purpose: Used in DES key schedule to rotate C and D halves each round.
'''

def circular_left_shift(bits, n):
    if not bits:
        return bits
    n = n % len(bits)
    return bits[n:] + bits[:n]


'''
Performs S-box substitution on a 48-bit binary input.
Input: b48 (48-bit binary string)
Output: 32-bit binary string
Purpose: Nonlinear transformation in each DES round for security.
'''

def sbox_substitution(b48):
    output = ''
    i = 0
    while i < 8:
        s = b48[i * 6:(i + 1) * 6]
        row = int(s[0] + s[5], 2)
        col = int(s[1:5], 2)
        output += bin(SBOXES[i][row][col])[2:].zfill(4)
        i += 1
    return output

'''
Executes the DES Feistel function (f-function).
Input: r (32-bit right half), k (48-bit subkey)
Output: 32-bit binary result after expansion, XOR, substitution, and permutation
Purpose: Core DES round function combining confusion and diffusion.
'''

def feistel_function(r, k):
    expanded = apply_permutation(r, EXPANSION_TABLE)
    xor_result = ''
    for i in range(48):
        xor_result += '1' if expanded[i] != k[i] else '0'
    substituted = sbox_substitution(xor_result)
    return apply_permutation(substituted, PBOX_PERMUTATION)

'''
Generates all 16 DES round subkeys (K1–K16) and intermediate C/D halves.
Input: kh (64-bit hex key)
Output: Cs (list of 28-bit C halves), Ds (list of 28-bit D halves), Ks (list of 48-bit subkeys)
Purpose: Builds DES key schedule used in all encryption/decryption rounds.
'''

def generate_subkeys(kh):
    key_bits = hex_to_binary(kh, 64)
    permuted_key = apply_permutation(key_bits, PERMUTATION_CHOICE_1)
    c = permuted_key[:28]
    d = permuted_key[28:]
    Cs = [c]
    Ds = [d]
    Ks = []
    for shift in KEY_SHIFTS_PER_ROUND:
        c = circular_left_shift(c, shift)
        d = circular_left_shift(d, shift)
        Cs.append(c)
        Ds.append(d)
        Ks.append(apply_permutation(c + d, PERMUTATION_CHOICE_2))
    return Cs, Ds, Ks

'''
Executes the 16-round DES Feistel structure.
Input: dh (64-bit hex data block), keys (list of 16 subkeys)
Output: out_bits (64-bit final binary), Ls (list of left halves), Rs (list of right halves)
Purpose: Performs the full encryption/decryption process depending on key order.
'''

def des_rounds(dh, keys):
    data_bits = hex_to_binary(dh, 64)
    ip = apply_permutation(data_bits, INITIAL_PERMUTATION)
    left = ip[:32]
    right = ip[32:]
    Ls = [left]
    Rs = [right]
    for k in keys:
        new_left = right
        f = feistel_function(right, k)
        new_right = ''
        for j in range(32):
            new_right += '1' if left[j] != f[j] else '0'
        left = new_left
        right = new_right
        Ls.append(left)
        Rs.append(right)
    preoutput = right + left
    out_bits = apply_permutation(preoutput, INVERSE_INITIAL_PERMUTATION)
    return out_bits, Ls, Rs

'''
Reads and parses the input text file for DES.
Input: p (file path)
Output: data (data block hex), key (key hex), operation ("encryption"/"decryption")
Purpose: Handles file input parsing for DES operations.
'''

def read_input_file(p):

    with open(p) as f:
        lines = f.read().strip().splitlines()
    data = key = operation = ''
    for line in lines:
        l = line.lower()
        if l.startswith('data_block:'):
            data = line.split(':')[1].strip().upper()
        elif l.startswith('key:'):
            key = line.split(':')[1].strip().upper()
        elif l.startswith('operation:'):
            operation = line.split(':')[1].strip().lower()
    return data, key, operation

'''
Writes all DES round data and the final result to a file.
Input: p (output path), Cs, Ds, Ks, Ls, Rs (round lists), res (final hex result)
Output: None (creates formatted output file)
Purpose: Produces output identical to required sample format.
'''

def write_results_file(p, Cs, Ds, Ks, Ls, Rs, res):

    with open(p, 'w') as f:
        for i in range(17):
            f.write(f'C{i}={Cs[i]}\nD{i}={Ds[i]}\n')
        f.write('\n')
        for i in range(16):
            f.write(f'K{i + 1}={Ks[i]}\n')
        f.write('\n')
        for i in range(17):
            f.write(f'L{i}={Ls[i]}\nR{i}={Rs[i]}\n')
        f.write('\nResult=' + res + '\n')

'''
Main entry point for the program.
Input: Command-line argument (input file path)
Output: Creates either program_results_output_encryption.txt or
        program_results_output_decryption.txt depending on the command executed. 
Purpose: Executes all of the DES steps (key generation, rounds, file I/O).
'''

import time

def main():

    if len(sys.argv) != 2:
        print('To use this program, be sure to run the following command <python3 DES.py your_input_file.txt>')
        sys.exit(1)

    start_time = time.time()

    inp = sys.argv[1]
    data, key, operation = read_input_file(inp)
    Cs, Ds, Ks_forward = generate_subkeys(key)
    Ks = Ks_forward[::-1] if operation == 'decryption' else Ks_forward
    bits, Ls, Rs = des_rounds(data, Ks)
    result_hex = binary_to_hex(bits)
    out_file = (
        'program_results_output_encryption.txt'
        if operation == 'encryption'
        else 'program_results_output_decryption.txt'
    )
    write_results_file(out_file, Cs, Ds, Ks, Ls, Rs, result_hex)

    end_time = time.time()
    runtime = end_time - start_time
    print('Success. The program has output the results to:', out_file)
    print(f'Runtime: {runtime:.6f} seconds')
