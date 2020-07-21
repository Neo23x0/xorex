#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# XORex XOR Key Extractor
# Florian Roth
#

import argparse
import collections
from colorama import init, Fore, Back, Style

__version__ = "0.1.0"

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
            byte_chain = fdata[i:(i+ws)].hex()
            stats['byte_stats'].update([byte_chain])

        all_stats.append(stats)

    return all_stats


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
    with open(input_file, 'rb') as fh:
        fdata = fh.read()
    # Try to decrypt the strings
    for s in KNOWN_STRINGS:
        print("Checking for known string: '%s' in the first %d bytes of the file" % (s.decode(), args.m))
        ws = len(s)

        # Loop over the most common key patterns
        for set in all_stats:
            most_common = set['byte_stats'].most_common(3)
            for key, count in most_common:
                # Go over file data and extract chunks in window size
                for i in range(0, args.m):
                    decrypted_code = de_xor(fdata[i:(i + ws)], bytearray.fromhex(key))
                    #print("S: %d E: %d CODE: %s" % (i, i+ws, decrypted_code))
                    if s in decrypted_code:
                        print("FOUND STRING IN DECRYPTED CODE WITH KEY: %s" % get_key_string(key))
                        print("DATA: '%s' OFFSET: %d DECRYPTED: '%s'" % (fdata[i:(i+ws)].hex(), i, decrypted_code.decode()))
                        # Try to determin junk data before the MZ header
                        mz_offset, rotated_key = find_mz_with_key(fdata[:i], key)
                        if rotated_key and mz_offset > 0:
                            print("It seems that the file has some kind of prefix (shellcode, junk etc.)")
                            print("Found MZ header at offset: %d" % mz_offset)
                            print("Adjusted XOR key to: %s" % get_key_string(rotated_key))


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
    parser.add_argument('-f', action='append', nargs='+', help='Path to input files',
                        metavar='input files')
    parser.add_argument('-w', help='Window Size (max. XOR key size)', metavar='max-window-size', default=10)
    parser.add_argument('-m', help='Maximum look into the file', metavar='max-offset', default=2048)
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

    all_stats = extract_byte_chains(args.f[0][0], args.w)
    print_guesses(all_stats)
    evaluate_keys(args.f[0][0], all_stats)
