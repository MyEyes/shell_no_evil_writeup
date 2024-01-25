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

if __name__ == "__main__":
    for i in range(27):
        print(hex(i))
        r_idx = 1
        add_val = u32(add_code) #turn add instruction into number
        add_val &= ~(0x1f << i) #mask 5 bits
        add_val |= r_idx << i #or with 1 to set bit again
        sc = p32(add_val) + crashing_code # modified addition + crash
        print(attempt(sc).decode())