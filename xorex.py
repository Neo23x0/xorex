#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# XORex XOR Key Extractor
# Florian Roth
#

import os
import re
import argparse
import collections
import hashlib
import pefile
import traceback
from colorama import init, Fore, Back, Style

__version__ = "0.2.0"

KNOWN_STRINGS = [b'This program', b'DOS mode']


def extract_byte_chains(input_file, window_size_max=10):
    """
    Extract byte chains
    :param input_file:
    :param window_size_max:
    :return:
    """
    # Read file
    fdata = []
    with open(input_file, 'rb') as fh:
        fdata = fh.read()

    # Read with increasing window size
    all_stats = []
    for ws in range(1, window_size_max+1):

        # Statistics
        stats = {
            'length': ws,
            'byte_stats': collections.Counter()
        }

        for i in range(0, len(fdata)):
            byte_chain = fdata[i:(i+ws)]
            if is_usable(byte_chain):
                stats['byte_stats'].update([byte_chain.hex()])

        all_stats.append(stats)

    return all_stats


def is_usable(byte_chain):
    """
    Is the byte chain usable as key
    :param byte_chain:
    :return:
    """
    # Skip zero byte keys
    only_zeros = True
    for c in byte_chain:
        if c != 0x00:
            only_zeros = False
    # Not usable
    if only_zeros:
        return False
    return True


def xor(data, key):
    """
    XORs data with a given key
    :param data:
    :param key:
    :return:
    """
    return bytearray(a ^ b for a, b in zip(*map(bytearray, [data, key])))


def de_xor(data, key):
    """
    Decode a bigger blob of data with a shorter key
    :param data:
    :param key:
    :return:
    """
    data_decoded = bytearray()
    i = 0
    while i < len(data):
        data_decoded += xor(data[i:i+len(key)], key)
        i += len(key)
    return data_decoded


def evaluate_keys(input_file, all_stats):
    """
    Try to find valid strings in decrypted data
    :param input_file:
    :param all_stats:
    :return:
    """
    # Read file
    print("\n" + Fore.BLACK + Back.WHITE + "=== Brute Forcing with the Evaluated Keys " + Style.RESET_ALL)
    fdata = []
    valid_keys = []
    with open(input_file, 'rb') as fh:
        fdata = fh.read()
    # Try to decrypt the strings
    for s in KNOWN_STRINGS:
        print("Checking for known string: '%s' in the first %d bytes of the file" % (s.decode(), int(args.m)))
        ws = len(s)

        # Loop over the most common key patterns
        for set in all_stats:
            most_common = set['byte_stats'].most_common(3)
            for key, count in most_common:
                # Go over file data and extract chunks in window size
                for i in range(0, int(args.m)):
                    decrypted_code = de_xor(fdata[i:(i + ws)], bytearray.fromhex(key))
                    #print("S: %d E: %d CODE: %s" % (i, i+ws, decrypted_code))
                    if s in decrypted_code:
                        print("FOUND STRING IN DECRYPTED CODE WITH KEY: %s" % get_key_string(key))
                        print("DATA: '%s' OFFSET: %d DECRYPTED: '%s'" % (fdata[i:(i+ws)].hex(), i, decrypted_code.decode()))
                        valid_keys.append({"key": key, "mz_offset": 0})
                        # Try to determin junk data before the MZ header
                        mz_offset, rotated_key = find_mz_with_key(fdata[:i], key)
                        if rotated_key and mz_offset > 0:
                            print("It seems that the file has some kind of prefix (shellcode, junk etc.)")
                            print("Found MZ header at offset: %d" % mz_offset)
                            print("Adjusted XOR key to: %s" % get_key_string(rotated_key))
                            valid_keys.append({"key": rotated_key, "mz_offset": mz_offset})
    # Return the valid keys
    return valid_keys


def get_key_string(key):
    """
    Prints key and a possible ASCII representation
    :param key:
    :return:
    """
    ascii_addon = ''
    ascii_key = get_ascii(key)
    if ascii_key:
        ascii_addon = Style.RESET_ALL + "ASCII '" + Fore.GREEN + "%s" % ascii_key + Style.RESET_ALL + "'"
    # Hex Value
    key_string = "HEX: '" + Fore.GREEN + '%s' % key + Style.RESET_ALL + "' %s" % ascii_addon
    return key_string


def find_mz_with_key(fdata, key):
    """
    Trying to find MZ header with key
    :param fdata:
    :param key:
    :return:
    """
    for j in range(0, int(len(key))):
        key_val = key[-j:] + key[:-j]
        for i in range(0, len(fdata)):
            decrypted_code = de_xor(fdata[i:(i + 2)], bytearray.fromhex(key_val))
            if b'MZ' == decrypted_code:
                return i, key_val
    return 0, ''


def decrypt_pe(input_file, valid_keys, output_path):
    """
    Decrypt the data blob and create files
    :param input_file:
    :param valid_keys:
    :param output_path:
    :return:
    """
    # We avoid the decryption of a duplicate files
    known_hashes = []

    print("\n" + Fore.BLACK + Back.WHITE + "=== Original File Recovery " + Style.RESET_ALL)
    with open(input_file, 'rb') as fh:
        fdata = fh.read()
    # Create output folder of not exists
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    # Try the different keys
    for vk in valid_keys:
        # Decrypt the data
        decrypted_data = de_xor(fdata[vk["mz_offset"]:], bytearray.fromhex(vk["key"]))
        # Test the resulting PE
        marker = ""
        color = Fore.BLUE
        if not test_pe(decrypted_data):
            print("The resulting PE file seems to be invalid - writing it nonetheless to disk for you to examine it")
            marker = "_likely_INVALID"
            color = Fore.RED
        # Create a file name in the output path
        filename = os.path.join(output_path, "%s_decrypted_%s%s.exe" % (
            os.path.splitext(os.path.basename(input_file))[0],
            vk["key"],
            marker
        ))
        print("Decrypting file with key '%s' and offset '%d' ..." % (vk["key"], vk["mz_offset"]))
        # Generate hash
        data_hash = hashlib.md5(decrypted_data).hexdigest()
        if data_hash not in known_hashes:
            print("Writing possible original file to " + color + "'%s'" % filename + Style.RESET_ALL + " ...")
            with open(filename, 'wb') as fh:
                fh.write(decrypted_data)
            known_hashes.append(data_hash)
        else:
            print("This file would be a duplicate. Skipping the output.")


def test_pe(fdata):
    """
    Test a PE file
    :param fdata:
    :return:
    """
    try:
        pe = pefile.PE(data=fdata)
    except pefile.PEFormatError as e:
        if args.debug:
            traceback.print_exc()
        return 0
    return 1


def get_ascii(key_bytes):
    """
    Try to get the key in ASCII
    :param key_bytes:
    :return:
    """
    ascii_key = ""
    try:
        ascii_key = bytearray.fromhex(key_bytes).decode('ascii')
    except UnicodeDecodeError as e:
        pass
    return ascii_key


def print_guesses(all_stats):
    """
    Print the top XOR key guesses
    :param all_stats:
    :return:
    """
    print(Fore.BLACK + Back.WHITE + "=== Statistics " + Style.RESET_ALL)
    print("List contains hex encoded key and count")
    for set in all_stats:
        length = set['length']
        most_common = set['byte_stats'].most_common(3)
        print("LENGTH: %d POSSIBLE XOR KEYS: %s" % (length, most_common))


if __name__ == '__main__':
    init(autoreset=False)
    # Parse Arguments
    parser = argparse.ArgumentParser(description='XOR Key Extractor')
    parser.add_argument('-f', help='Path to input file', metavar='input_file')
    parser.add_argument('-w', help='Window Size (max. XOR key size)', metavar='max-window-size', default=10)
    parser.add_argument('-m', help='Maximum look into the file', metavar='max-offset', default=10240)
    parser.add_argument('-o', help='Output Path for decrypted PE files', metavar='output-path', default="./output")

    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    print(Style.RESET_ALL)
    print(Fore.BLACK + Back.WHITE)
    print(" ")
    print("      _  ______  ___  _____  __ ")
    print("     | |/_/ __ \\/ _ \\/ __/ |/_/ ")
    print("    _>  </ /_/ / , _/ _/_>  <   ")
    print("   /_/|_|\\____/_/|_/___/_/|_|   ")
    print(" ")
    print("   XOR Key Evaluator for Encrypted Executables")
    print("   Florian Roth, July 2020, %s " % __version__)
    print(" ".ljust(80) + Style.RESET_ALL)
    print(" ")

    all_stats = extract_byte_chains(input_file=args.f, window_size_max=args.w)
    print_guesses(all_stats=all_stats)
    valid_keys = evaluate_keys(input_file=args.f, all_stats=all_stats)
    decrypt_pe(input_file=args.f, valid_keys=valid_keys, output_path=args.o)
