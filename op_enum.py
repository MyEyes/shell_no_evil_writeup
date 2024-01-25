from pwn import *
from sw64 import add, t12, t8
context.log_level = "error" #get rid of annoying connect disconnect prints
add_code = b"\x00\x00\x11\x42"
crashing_code = b"\x00\x00\x11\x74"

def attempt(shellcode):
    with remote("localhost", 5000) as r:
        r.recvuntil(b"(0 to use the builtin): ")
        r.sendline(f"{len(shellcode)}".encode())
        r.recvuntil(b"bytes of shellcode: ")
        r.send(shellcode)
        return r.clean(timeout=0.5)

def op(dst,r1,r2, mod):
    op_val = 0x00000000 
    op_val |= dst 
    op_val |= mod << 0x1a #Modify the op code
    op_val |= r1 << 0x10
    op_val |= r2 << 0x15
    return p32(op_val) #encode

if __name__ == "__main__":
    for i in range(64):
        print(hex(i))
        payload = add(t12,t12,t8) #Add some offset to t12 so we're in the middle of the page
        payload += op(t12,t12,t12,i) #Try out our operation
        payload += crashing_code #Crash so we can read registers
        payload += b"A"*(4096-len(payload)) #Fill with As
        print(attempt(payload).decode())