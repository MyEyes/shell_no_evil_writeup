from pwn import *
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

def add(dst,r1,r2, mod):
    add_val = 0x40000000 #decoded and masked value that means 32-bit add
    #or registers into instruction
    add_val |= dst 
    add_val |= mod << 0x5
    add_val |= r1 << 0x10
    add_val |= r2 << 0x15
    return p32(add_val) #encode

if __name__ == "__main__":
    for i in range(1024):
        print(hex(i))
        add_val = add(21,22,23, i) #add: a5=t8+t9
        sc = add_val + crashing_code # modified addition + crash
        print(attempt(sc).decode())