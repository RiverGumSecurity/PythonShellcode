#!/usr/bin/env python3

import argparse
import numpy
import sys


def xorstr(data, k):
    m = int(len(data) / len(k))
    r = len(data) % len(k)
    newkey = k * m + k[:r]
    res = numpy.bitwise_xor(bytearray(data), bytearray(newkey))
    return bytes(res)

def print_bytedata(d):
    print('    buf = b""')
    line = ''
    for i, ch in enumerate(d):
        if i and not i % 16:
            print(f'    buf += b"{line}"')
            line = ''
        line += f'\\x{ch:02x}'
    if i % 16:
        print(f'    buf += b"{line}"')

if __name__ == '__main__':
    print('''\
 _______________________________________________________

    xorme.py: Shellcode encryptor using XOR function.
    Version 1.0 (c) Joff Thyer
    Black Hills Information Security LLC
    River Gum Security LLC
  _______________________________________________________
''')
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-k', default='encryptme',
        help='encryption key (default="encryptme")')
    parser.add_argument(
        '-f', default='', help='raw shellcode file name')
    args = parser.parse_args()
    if args.f:
        with open(args.f, 'rb') as fh:
            data = fh.read()
    else:
        data = sys.stdin.buffer.read()
    res = xorstr(data.encode(), args.k.encode())
    print_bytedata(res)
