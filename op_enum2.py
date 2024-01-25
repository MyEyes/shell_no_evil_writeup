from pwn import *
from sw64 import add, t12, t8, sp, v0
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

def load(dst,src_reg):
    op_val = 0x00000000 
    op_val |= dst << 0x15
    op_val |= src_reg << 0x10
    op_val |= 0x23 << 0x1a #Modify the op code
    return p32(op_val) #encode

def op(dst,src_reg, mod):
    op_val = 0x00000000 
    op_val |= dst << 0x15
    op_val |= src_reg << 0x10
    op_val |= mod << 0x1a #Modify the op code
    return p32(op_val) #encode

if __name__ == "__main__":
    for i in range(64):
        print(hex(i))
        payload = op(t12,sp,i) #Try out our operation, to write t12 to [sp]
        payload += load(v0, sp) #Load from sp into v0
        payload += crashing_code #Crash so we can read registers
        print(attempt(payload).decode())